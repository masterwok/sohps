package hijack

import (
	"path/filepath"
	"strings"

	"github.com/masterwok/sohps/internal/fs"
)

func Analyze(rawPaths []string, libs []string, targetPath string, machineType string) []*HijackCandidate {
	isSecure := fs.IsATSecure(targetPath)
	searchPaths := buildSearchPaths(rawPaths, targetPath, isSecure, machineType)
	hijackCandidates := []*HijackCandidate{}

	for _, lib := range libs {
		// If a DT_NEEDED entry contains a '/', ld.so treats it as a direct path
		// (either absolute or relative to CWD) and bypasses all search paths.
		if strings.Contains(lib, "/") {
			resolvedLib := lib
			if !filepath.IsAbs(lib) {
				if abs, err := filepath.Abs(lib); err == nil {
					resolvedLib = abs
				}
			}
			hijackCandidates = append(hijackCandidates, checkAbsPathLib(resolvedLib))
		} else {
			hijackCandidates = append(hijackCandidates, checkSearchPathLib(searchPaths, lib, machineType)...)
		}
	}

	return hijackCandidates
}

// huntSearchPathLib iterates through the dynamic linker's search paths.
// It returns a slice of all viable hijack candidates found along the route.
func checkSearchPathLib(searchPaths []SearchPath, libName string, machineType string) []*HijackCandidate {
	var candidates []*HijackCandidate

	for _, path := range searchPaths {
		if path.Resolved == "CWD_HIJACK_VECTOR" {
			candidate := &HijackCandidate{
				Library:     libName,
				Category:    "Implicit CWD",
				RawRunPath:  path.Raw,
				ResolvedDir: "Runtime Current Working Directory",
				CanHijack:   true,
				Action:      "CWD HIJACK: Execute binary from an attacker-controlled writable directory containing a malicious payload.",
			}
			candidates = append(candidates, candidate)
			continue
		}

		category := "System Path"
		if strings.Contains(path.Raw, "$ORIGIN") || strings.Contains(path.Raw, "${ORIGIN}") {
			category = "$ORIGIN Hijack"
		} else if !filepath.IsAbs(path.Raw) {
			category = "Relative Path"
		} else if fs.IsWritable(path.Resolved) {
			category = "Writable Path"
		} else if parent, found := fs.FindWritableParent(path.Resolved); found {
			_ = parent // parent found, so it's a writable path via recreation
			category = "Writable Path"
		}

		hwcapPaths := getHWCAPPaths(path.Resolved, machineType)
		
		// Pass 1: Does the file exist anywhere in this search path segment?
		// ld.so stops searching globally once the file is found.
		var existingPath string
		for _, hwcapDir := range hwcapPaths {
			fullPath := filepath.Join(hwcapDir, libName)
			if fs.FileExists(fullPath) {
				existingPath = hwcapDir
				break
			}
		}

		if existingPath != "" {
			// The file exists in this segment. Evaluate ONLY this path.
			fullPath := filepath.Join(existingPath, libName)
			candidate := &HijackCandidate{
				Library:     libName,
				Category:    category,
				RawRunPath:  path.Raw,
				ResolvedDir: existingPath,
			}
			
			candidate.CanHijack, candidate.Action = evaluateHijackVector(fullPath, existingPath, true)
			
			if candidate.CanHijack {
				candidates = append(candidates, candidate)
			}
			
			// Linker stops searching completely once file is found
			break
		}

		// Pass 2: The file is missing. Find the highest-priority HWCAP dir we can drop it into.
		for _, hwcapDir := range hwcapPaths {
			fullPath := filepath.Join(hwcapDir, libName)
			candidate := &HijackCandidate{
				Library:     libName,
				Category:    category,
				RawRunPath:  path.Raw,
				ResolvedDir: hwcapDir,
			}

			candidate.CanHijack, candidate.Action = evaluateHijackVector(fullPath, hwcapDir, false)

			if candidate.CanHijack {
				candidates = append(candidates, candidate)
				// Break after finding the highest-priority writable drop location for this path segment
				break
			}
		}
	}

	return candidates
}

// checkAbsPathLib evaluates an absolute path to a shared library and determines
// if the path or its parent directory is vulnerable to hijacking.
func checkAbsPathLib(libPath string) *HijackCandidate {
	targetDir := filepath.Dir(libPath)
	fileExists := fs.FileExists(libPath)

	candidate := HijackCandidate{
		Library:     libPath,
		Category:    "Absolute Path",
		RawRunPath:  "Hardcoded Absolute Path",
		ResolvedDir: targetDir,
	}

	candidate.CanHijack, candidate.Action = evaluateHijackVector(libPath, targetDir, fileExists)

	return &candidate
}
