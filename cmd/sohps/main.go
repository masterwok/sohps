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
	args := parseArgs()

	report.Init(args.Verbose, args.NoColor)

	fs.RootPath = args.RootPath
	audit.CheckSystemPreload(args.RootPath)

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

		// Progress tracker
		count := 0
		for range results {
			count++
			if args.IsDirectoryScan && count%100 == 0 {
				fmt.Printf("\r[*] Progress: [%d/%d] %.1f%%", count, totalFiles, float64(count)/float64(totalFiles)*100)
			}
			if count == totalFiles {
				break
			}
		}
		if args.IsDirectoryScan {
			fmt.Printf("\r[*] Progress: [%d/%d] 100.0%%\n", totalFiles, totalFiles)
		}

		wg.Wait()
		fmt.Println("[*] Scan complete.")

	} else {
		processBinary(args.TargetPath, args)
	}
}

func processBinary(path string, args *Args) {
	f, err := elfparser.GetHandle(path)
	if err != nil {
		return
	}
	defer f.Close()

	libs, err := elfparser.GetRequiredLibraries(f)
	if err != nil {
		return
	}

	rawPaths := elfparser.ExtractRawSearchPaths(f, args.LDLibraryPath, args.RootPath)
	candidates := hijack.Analyze(rawPaths, libs, path, f.Machine.String(), args.RootPath)

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

func parseArgs() *Args {
	ldPath := flag.String("ld-path", "", "Simulate LD_LIBRARY_PATH environment variable (colon-separated)")
	rootPath := flag.String("root", "/", "Specify base system root for global audits (e.g. /etc/ld.so.preload)")
	verbose := flag.Bool("v", false, "Enable verbose output (print safe targets)")
	noColor := flag.Bool("nc", false, "Disable color output")

	flag.Parse()

	args := flag.Args()

	if len(args) != 1 {
		fmt.Printf("SOHPS: Shared Object Hijack Path Scanner\n\n")
		fmt.Printf("Usage: %s [-v] [-nc] [--root <path>] [--ld-path <paths>] <target_binary_or_dir>\n\n", os.Args[0])
		fmt.Printf("Flags:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	return &Args{
		TargetPath:    args[0],
		LDLibraryPath: *ldPath,
		RootPath:      *rootPath,
		Verbose:       *verbose,
		NoColor:       *noColor,
	}
}
