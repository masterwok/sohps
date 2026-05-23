package report

import (
	"fmt"
	"os"
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
		raw      string
		resolved string
		action   string
	}
	groups := make(map[groupKey][]string)
	categories := make(map[groupKey]string)

	for _, c := range candidates {
		if !c.CanHijack {
			continue
		}
		key := groupKey{c.RawRunPath, c.ResolvedDir, c.Action}
		groups[key] = append(groups[key], c.Library)
		categories[key] = c.Category
	}

	for key, libs := range groups {
		fmt.Printf("    %s%s[!] %s%s\n", Red, Bold, categories[key], Reset)
		fmt.Printf("    %-15s : %s\n", "Vulnerable Path", key.raw)
		fmt.Printf("    %-15s : %s\n", "Resolved Dir", key.resolved)
		fmt.Printf("    %-15s : %s\n", "Action", key.action)
		fmt.Printf("    %-15s : %s\n\n", fmt.Sprintf("Libraries (%d)", len(libs)), strings.Join(libs, ", "))
	}
}
