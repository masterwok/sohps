package audit

import (
	"path/filepath"

	"github.com/masterwok/sohps/internal/fs"
	"github.com/masterwok/sohps/internal/hijack"
)

// CheckSystemPreload evaluates the global ld.so.preload file for vulnerabilities relative to a root path.
func CheckSystemPreload(root string) []*hijack.HijackCandidate {
	preloadPath := filepath.Join(root, "etc", "ld.so.preload")
	etcDir := filepath.Join(root, "etc")
	return RunPreloadAudit(preloadPath, etcDir)
}

// RunPreloadAudit performs the actual check on the specified paths.
func RunPreloadAudit(preloadPath, etcDir string) []*hijack.HijackCandidate {
	var candidates []*hijack.HijackCandidate

	if fs.FileExists(preloadPath) && fs.IsWritable(preloadPath) {
		candidates = append(candidates, &hijack.HijackCandidate{
			Category:    "System Preload",
			RawRunPath:  preloadPath,
			ResolvedDir: preloadPath,
			Action:      "PRELOAD INJECT: Append malicious payload path directly to " + preloadPath,
			Library:     "ld.so.preload",
			CanHijack:   true,
		})
	}

	if !fs.FileExists(preloadPath) && fs.IsWritable(etcDir) {
		candidates = append(candidates, &hijack.HijackCandidate{
			Category:    "System Preload",
			RawRunPath:  preloadPath,
			ResolvedDir: etcDir + " (Missing)",
			Action:      "PRELOAD CREATE: Create " + preloadPath + " and add malicious payload path",
			Library:     "ld.so.preload",
			CanHijack:   true,
		})
	}

	return candidates
}
