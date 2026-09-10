package hijack

import (
	"path/filepath"
	"strings"

	"github.com/masterwok/sohps/internal/fs"
)

func Analyze(rawPaths []SearchPath, directLibs []string, transitiveLibs []string, proxyReqMap map[string]bool, targetPath string, machineType string, root string) []*HijackCandidate {
	hijackCandidates := []*HijackCandidate{}

	// Evaluate Direct Dependencies (Subject to RUNPATH/RPATH)
	for _, lib := range directLibs {
		if strings.Contains(lib, "/") {
			hijackCandidates = append(hijackCandidates, checkAbsPathLib(lib, "Direct", proxyReqMap[lib], root))
		} else {
			hijackCandidates = append(hijackCandidates, checkSearchPathLib(rawPaths, lib, machineType, "Direct", proxyReqMap[lib], root)...)
		}
	}

	// Evaluate Transitive Dependencies (Only subject to system-wide paths and RPATH, but we skip RUNPATH here)
	// We extract only the system paths from rawPaths to evaluate transitive dependencies correctly.
	systemPaths := []SearchPath{}
	for _, p := range rawPaths {
		if filepath.IsAbs(p.Raw) && !strings.Contains(p.Raw, "$ORIGIN") {
			systemPaths = append(systemPaths, p)
		}
	}

	for _, lib := range transitiveLibs {
		if strings.Contains(lib, "/") {
			hijackCandidates = append(hijackCandidates, checkAbsPathLib(lib, "Transitive", proxyReqMap[lib], root))
		} else {
			hijackCandidates = append(hijackCandidates, checkSearchPathLib(systemPaths, lib, machineType, "Transitive", proxyReqMap[lib], root)...)
		}
	}

	for _, c := range hijackCandidates {
		c.Binary = targetPath
	}

	return hijackCandidates
}

// huntSearchPathLib iterates through the dynamic linker's search paths.
// It returns a slice of all viable hijack candidates found along the route.
func checkSearchPathLib(searchPaths []SearchPath, libName string, machineType string, depType string, proxyRequired bool, root string) []*HijackCandidate {
	var candidates []*HijackCandidate

	for _, path := range searchPaths {
		if path.Resolved == "CWD_HIJACK_VECTOR" {
			// RUNPATH is non-transitive! If we are evaluating a transitive library
			// against an empty RUNPATH from the main binary, it is a false positive.
			if depType == "Transitive" {
				continue
			}

			candidate := &HijackCandidate{
				Library:        libName,
				Category:       "Implicit CWD",
				RawRunPath:     path.Raw,
				ResolvedDir:    "Runtime Current Working Directory",
				CanHijack:      true,
				Action:         "CWD HIJACK: Execute binary from an attacker-controlled writable directory containing a malicious payload.",
				DependencyType: depType,
				ProxyRequired:  proxyRequired,
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
		} else if _, found := fs.FindWritableParent(path.Resolved, root); found {
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
				Library:        libName,
				Category:       category,
				RawRunPath:     path.Raw,
				ResolvedDir:    existingPath,
				DependencyType: depType,
				ProxyRequired:  proxyRequired,
			}

			candidate.CanHijack, candidate.Action = evaluateHijackVector(fullPath, existingPath, root, true)

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
				Library:        libName,
				Category:       category,
				RawRunPath:     path.Raw,
				ResolvedDir:    hwcapDir,
				DependencyType: depType,
				ProxyRequired:  proxyRequired,
			}

			candidate.CanHijack, candidate.Action = evaluateHijackVector(fullPath, hwcapDir, root, false)

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
func checkAbsPathLib(libPath string, depType string, proxyRequired bool, root string) *HijackCandidate {
	resolvedLib := libPath
	// Prefix with root if it's an absolute path and not already prefixed.
	if filepath.IsAbs(libPath) && root != "/" && root != "" {
		if !strings.HasPrefix(libPath, root) {
			resolvedLib = filepath.Join(root, libPath)
		}
	}

	targetDir := filepath.Dir(resolvedLib)
	fileExists := fs.FileExists(resolvedLib)

	candidate := HijackCandidate{
		Library:        libPath,
		Category:       "Absolute Path",
		RawRunPath:     "Hardcoded Absolute Path",
		ResolvedDir:    targetDir,
		DependencyType: depType,
		ProxyRequired:  proxyRequired,
	}

	candidate.CanHijack, candidate.Action = evaluateHijackVector(resolvedLib, targetDir, root, fileExists)

	return &candidate
}
