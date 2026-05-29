package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/masterwok/sohps/internal/audit"
	"github.com/masterwok/sohps/internal/elfparser"
	"github.com/masterwok/sohps/internal/fs"
	"github.com/masterwok/sohps/internal/hijack"
	"github.com/masterwok/sohps/internal/report"
	"github.com/masterwok/sohps/internal/scanner"
)

var printMutex sync.Mutex

type Args struct {
	TargetPath      string
	LDLibraryPath   string
	RootPath        string
	IsDirectoryScan bool
	Verbose         bool
	NoColor         bool
}

func main() {
	args, err := parseArgs()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	report.Init(args.Verbose, args.NoColor)

	fs.RootPath = args.RootPath
	globalCandidates := audit.CheckSystemPreload(args.RootPath)
	if len(globalCandidates) > 0 {
		report.PrintTarget("Global System Audit")
		report.PrintFindings(globalCandidates)
	}

	info, err := os.Stat(args.TargetPath)
	if err != nil {
		report.PrintErrorAndExit(err)
	}

	if info.IsDir() {
		args.IsDirectoryScan = true
		fmt.Printf("%s[*] Scanning %s...%s\n", report.Yellow, args.TargetPath, report.Reset)

		targetFiles, err := scanner.DiscoverBinaries(args.TargetPath, args.RootPath)
		if err != nil {
			report.PrintErrorAndExit(err)
		}

		totalFiles := len(targetFiles)
		fmt.Printf("%s[*] Found %d ELF binaries. Starting analysis...%s\n\n", report.Gray, totalFiles, report.Reset)

		if totalFiles == 0 {
			return
		}

		// Initialize worker pool
		numWorkers := runtime.NumCPU()
		jobs := make(chan string, totalFiles)
		results := make(chan bool, totalFiles)
		var wg sync.WaitGroup

		for w := 0; w < numWorkers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for path := range jobs {
					processBinary(path, args)
					results <- true
				}
			}()
		}

		// Queue all jobs
		for _, path := range targetFiles {
			jobs <- path
		}
		close(jobs)

		go func() {
			wg.Wait()
			close(results)
		}()

		// Progress tracker
		count := 0
		for range results {
			count++
			if args.IsDirectoryScan && count%100 == 0 {
				fmt.Printf("\r[*] Progress: [%d/%d] %.1f%%", count, totalFiles, float64(count)/float64(totalFiles)*100)
			}
		}
		if args.IsDirectoryScan {
			fmt.Printf("\r[*] Progress: [%d/%d] 100.0%%\n", totalFiles, totalFiles)
		}
		fmt.Println("[*] Scan complete.")

	} else {
		processBinary(args.TargetPath, args)
	}
}

func processBinary(path string, args *Args) {
	var candidates []*hijack.HijackCandidate

	f, err := elfparser.GetHandle(path)
	if err != nil {
		return
	}
	defer f.Close()

	// 1. Extract direct dependencies
	directLibs, err := elfparser.GetRequiredLibraries(f)
	if err != nil {
		directLibs = []string{}
	}

	// 2. Resolve all transitive dependencies
	allLibsMap, proxyReqMap, err := elfparser.ResolveTransitiveDependencies(path, directLibs, nil, args.LDLibraryPath, args.RootPath)
	if err != nil {
		allLibsMap = make(map[string]string)
		for _, l := range directLibs {
			allLibsMap[l] = ""
		}
		proxyReqMap = make(map[string]bool)
	}

	// Calculate transitive-only libraries (allLibs - directLibs)
	directMap := make(map[string]bool)
	for _, l := range directLibs {
		directMap[l] = true
	}

	var transitiveLibs []string
	for l := range allLibsMap {
		if !directMap[l] {
			transitiveLibs = append(transitiveLibs, l)
		}
	}

	// 3. Check for Container Runtime vulnerabilities (e.g. AppImage)
	if elfparser.IsAppImage(path) {
		offset := elfparser.GetAppImageOffset(path)
		if offset > 0 {
			var allLibsList []string
			for l := range allLibsMap {
				allLibsList = append(allLibsList, l)
			}
			candidates = append(candidates, audit.AuditAppImage(path, offset, allLibsList)...)
		}
	}

	// 4. ELF Analysis
	rawPaths := elfparser.ExtractRawSearchPaths(f, args.LDLibraryPath, args.RootPath)
	// We need to pass the machine type and root correctly
	hijackSearchPaths := hijack.BuildSearchPaths(rawPaths, path, fs.IsATSecure(path), f.Machine.String(), args.RootPath)

	elfCandidates := hijack.Analyze(hijackSearchPaths, directLibs, transitiveLibs, proxyReqMap, path, f.Machine.String(), args.RootPath)
	candidates = append(candidates, elfCandidates...)

	hasFindings := false
	for _, c := range candidates {
		if c.CanHijack {
			hasFindings = true
			break
		}
	}

	if hasFindings || args.Verbose {
		printMutex.Lock()
		if args.IsDirectoryScan {
			fmt.Print("\r\033[K")
		}

		if hasFindings {
			report.PrintTarget(path)
			report.PrintFindings(candidates)
		} else {
			report.PrintSafeTarget(path)
		}

		printMutex.Unlock()
	}
}

func parseArgs() (*Args, error) {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	ldPath := flag.String("ld-path", "", "Simulate LD_LIBRARY_PATH environment variable (colon-separated)")
	rootPath := flag.String("root", "/", "Specify base system root for global audits (e.g. /etc/ld.so.preload)")
	verbose := flag.Bool("v", false, "Enable verbose output (print safe targets)")
	noColor := flag.Bool("nc", false, "Disable color output")

	flag.Parse()

	args := flag.Args()

	if len(args) != 1 {
		return nil, fmt.Errorf("SOHPS: Shared Object Hijack Path Scanner\n\nUsage: %s [-v] [-nc] [--root <path>] [--ld-path <paths>] <target_binary_or_dir>\n\nFlags:\n%s", os.Args[0], getFlagDefaults())
	}

	return &Args{
		TargetPath:    args[0],
		LDLibraryPath: *ldPath,
		RootPath:      *rootPath,
		Verbose:       *verbose,
		NoColor:       *noColor,
	}, nil
}

func getFlagDefaults() string {
	var output string
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		output += fmt.Sprintf("  -%s=%s: %s\n", f.Name, f.DefValue, f.Usage)
	})
	return output
}
