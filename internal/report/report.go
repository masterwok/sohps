package report

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/masterwok/sohps/internal/hijack"
)

var (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Red     = "\033[31m" // Standard Red
	Blue    = "\033[34m" // Standard Blue
	Gray    = "\033[90m" // Dark Gray (Bright Black)
	Green   = "\033[32m" // Standard Green
	Yellow  = "\033[33m" // Standard Yellow
	Magenta = "\033[35m" // Standard Magenta
	Cyan    = "\033[36m" // Standard Cyan
)

var (
	isVerbose bool
	noColor   bool
)

// Init initializes the reporting package with user preferences.
func Init(verbose bool, disableColor bool) {
	isVerbose = verbose
	noColor = disableColor

	if noColor {
		Reset = ""
		Bold = ""
		Red = ""
		Blue = ""
		Gray = ""
		Green = ""
		Yellow = ""
		Magenta = ""
		Cyan = ""
	} else {
		Reset = "\033[0m"
		Bold = "\033[1m"
		Red = "\033[31m"
		Blue = "\033[34m"
		Gray = "\033[90m"
		Green = "\033[32m"
		Yellow = "\033[33m"
		Magenta = "\033[35m"
		Cyan = "\033[36m"
	}
}

// PrintErrorAndExit prints an error message and terminates the program.
func PrintErrorAndExit(err error) {
	fmt.Printf("%s[-] Error: %v%s\n", Red, err, Reset)
	os.Exit(1)
}

// PrintTarget prints the path currently being analyzed.
func PrintTarget(path string) {
	fmt.Printf("%s[*] %s%s\n", Yellow, path, Reset)
}

// PrintSafeTarget prints a message indicating no vulnerabilities were found (only in verbose mode).
func PrintSafeTarget(path string) {
	if isVerbose {
		fmt.Printf("%s[+] %s (Safe)%s\n", Gray, path, Reset)
	}
}

// PrintFindings formats and displays verified privilege escalation candidates.
func PrintFindings(candidates []*hijack.HijackCandidate) {
	type groupKey struct {
		category string
		resolved string
		action   string
	}

	type libInfo struct {
		name          string
		depType       string
		proxyRequired bool
		isEnvVar      bool
	}

	groups := make(map[groupKey][]libInfo)
	rawPaths := make(map[groupKey]map[string]bool)

	for _, c := range candidates {
		if !c.CanHijack {
			continue
		}
		key := groupKey{c.Category, c.ResolvedDir, c.Action}

		// Add library if not already in this group
		found := false
		for _, l := range groups[key] {
			if l.name == c.Library {
				found = true
				break
			}
		}
		if !found {
			groups[key] = append(groups[key], libInfo{c.Library, c.DependencyType, c.ProxyRequired, c.IsEnvVar})
		}

		// Track unique raw paths for this group
		if rawPaths[key] == nil {
			rawPaths[key] = make(map[string]bool)
		}
		rawPaths[key][c.RawRunPath] = true
	}

	for key, libs := range groups {
		paths := []string{}
		for p := range rawPaths[key] {
			paths = append(paths, p)
		}

		// Sort libraries: Constructor Injection first, then Direct first, then alphabetical
		sort.Slice(libs, func(i, j int) bool {
			if libs[i].proxyRequired != libs[j].proxyRequired {
				return !libs[i].proxyRequired
			}
			if libs[i].depType != libs[j].depType {
				return libs[i].depType == "Direct"
			}
			return libs[i].name < libs[j].name
		})

		var constructorTagPrinted bool
		var proxyTagPrinted bool
		isEnvVarGroup := false

		formattedLibs := make([]string, len(libs))
		for i, l := range libs {
			if l.isEnvVar {
				isEnvVarGroup = true
				formattedLibs[i] = l.name
				continue
			}

			tag := ""
			if l.proxyRequired {
				if !proxyTagPrinted {
					tag = " (Proxy Required)"
					proxyTagPrinted = true
				}
			} else {
				if !constructorTagPrinted {
					tag = " (Constructor Injection)"
					constructorTagPrinted = true
				}
			}
			formattedLibs[i] = fmt.Sprintf("%s%s", l.name, tag)
		}

		label := "Libraries"
		if isEnvVarGroup {
			label = "Variables"
		}

		fmt.Printf("    %s%s[!] %s%s\n", Red, Bold, key.category, Reset)
		fmt.Printf("    %-15s : %s\n", "Vulnerable Path", strings.Join(paths, ", "))
		fmt.Printf("    %-15s : %s\n", "Resolved Dir", key.resolved)
		fmt.Printf("    %-15s : %s\n", "Action", key.action)
		fmt.Printf("    %-15s : %s\n\n", fmt.Sprintf("%s (%d)", label, len(libs)), strings.Join(formattedLibs, "\n                      "))
	}
}
