package audit

import (
	"fmt"
	"path/filepath"

	"github.com/masterwok/sohps/internal/fs"
	"github.com/masterwok/sohps/internal/report"
)

// CheckSystemPreload evaluates the global ld.so.preload file for vulnerabilities relative to a root path.
func CheckSystemPreload(root string) {
	preloadPath := filepath.Join(root, "etc", "ld.so.preload")
	etcDir := filepath.Join(root, "etc")
	RunPreloadAudit(preloadPath, etcDir)
}

// RunPreloadAudit performs the actual check on the specified paths.
func RunPreloadAudit(preloadPath, etcDir string) {
	if fs.FileExists(preloadPath) && fs.IsWritable(preloadPath) {
		report.PrintTarget(preloadPath)
		fmt.Printf("    %s%s[!] System Preload%s\n", report.Red, report.Bold, report.Reset)
		fmt.Printf("    %-15s : %s\n", "Vulnerable Path", preloadPath)
		fmt.Printf("    %-15s : %s\n", "Resolved Dir", preloadPath)
		fmt.Printf("    %-15s : PRELOAD INJECT: Append malicious payload path directly to %s\n\n", "Action", preloadPath)
	}

	if !fs.FileExists(preloadPath) && fs.IsWritable(etcDir) {
		report.PrintTarget(preloadPath)
		fmt.Printf("    %s%s[!] System Preload%s\n", report.Red, report.Bold, report.Reset)
		fmt.Printf("    %-15s : %s\n", "Vulnerable Path", preloadPath)
		fmt.Printf("    %-15s : %s (Missing)\n", "Resolved Dir", etcDir)
		fmt.Printf("    %-15s : PRELOAD CREATE: Create %s and add malicious payload path\n\n", "Action", preloadPath)
	}
}
