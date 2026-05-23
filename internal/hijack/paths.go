package hijack

import (
	"path/filepath"
	"strings"
)

// getHWCAPPaths returns the prioritized list of subdirectories glibc searches
// within a given base path based on the machine architecture.
func getHWCAPPaths(basePath, machineType string) []string {
	arch := "unknown"
	switch machineType {
	case "EM_X86_64":
		arch = "x86_64"
	case "EM_386":
		arch = "i386"
	case "EM_AARCH64":
		arch = "aarch64"
	case "EM_ARM":
		arch = "arm"
	}

	return []string{
		filepath.Join(basePath, "tls", arch, arch),
		filepath.Join(basePath, "tls", arch),
		filepath.Join(basePath, "tls"),
		filepath.Join(basePath, arch, arch),
		filepath.Join(basePath, arch),
		basePath, // Always check the base path last
	}
}

// buildSearchPaths takes a list of raw paths and the target binary path,
// expanding linker macros and resolving relative traversals.
// If isSecure is true (SUID/SGID), it mimics ld.so AT_SECURE behavior by
// dropping $ORIGIN and relative paths.
func buildSearchPaths(rawPaths []string, targetBinary string, isSecure bool, machineType string) []SearchPath {
	var searchPaths []SearchPath

	// ld.so resolves $ORIGIN relative to the binary's actual location
	binaryDir := filepath.Dir(targetBinary)

	// Determine $LIB and $PLATFORM expansions based on ELF Machine type
	libMacro := "lib"
	platformMacro := "unknown"
	
	switch machineType {
	case "EM_X86_64":
		libMacro = "lib64"
		platformMacro = "x86_64"
	case "EM_386":
		libMacro = "lib"
		platformMacro = "i386"
	case "EM_AARCH64":
		libMacro = "lib64"
		platformMacro = "aarch64"
	case "EM_ARM":
		libMacro = "lib"
		platformMacro = "arm"
	}

	for _, raw := range rawPaths {
		// Mimic AT_SECURE behavior: Ignore $ORIGIN, relative paths, and empty paths (CWD)
		if isSecure {
			if strings.Contains(raw, "$ORIGIN") || strings.Contains(raw, "${ORIGIN}") {
				continue
			}
			if !filepath.IsAbs(raw) {
				// This catches both relative paths like "lib/" and empty paths ""
				continue
			}
		}

		resolved := raw

		// Expand the $ORIGIN macro (handles both common syntax variations)
		if strings.Contains(resolved, "$ORIGIN") {
			resolved = strings.ReplaceAll(resolved, "$ORIGIN", binaryDir)
		} else if strings.Contains(resolved, "${ORIGIN}") {
			resolved = strings.ReplaceAll(resolved, "${ORIGIN}", binaryDir)
		}

		// Expand $LIB macro
		if strings.Contains(resolved, "$LIB") {
			resolved = strings.ReplaceAll(resolved, "$LIB", libMacro)
		} else if strings.Contains(resolved, "${LIB}") {
			resolved = strings.ReplaceAll(resolved, "${LIB}", libMacro)
		}

		// Expand $PLATFORM macro
		if strings.Contains(resolved, "$PLATFORM") {
			resolved = strings.ReplaceAll(resolved, "$PLATFORM", platformMacro)
		} else if strings.Contains(resolved, "${PLATFORM}") {
			resolved = strings.ReplaceAll(resolved, "${PLATFORM}", platformMacro)
		}

		// If the path evaluates to empty (e.g. trailing colon), it is an implicit CWD load.
		// We MUST NOT pass this to filepath.Abs, otherwise we evaluate the vulnerability
		// of the tool's execution directory rather than warning about the CWD vector generally.
		if resolved == "" {
			searchPaths = append(searchPaths, SearchPath{
				Raw:      "Empty Path (Implicit CWD)",
				Resolved: "CWD_HIJACK_VECTOR",
			})
			continue
		}

		// Resolve to an absolute path.
		// If a RUNPATH is strictly relative (e.g., "lib/") without $ORIGIN,
		// ld.so resolves it relative to the Current Working Directory.
		// filepath.Abs() safely handles this relative to the tool's execution context.
		absPath, err := filepath.Abs(resolved)
		if err == nil {
			resolved = absPath
		}

		// Clean the path, but evaluate symlinks to mirror real OS behavior.
		// If EvalSymlinks fails (e.g., path doesn't exist yet), we fall back to lexical Clean.
		if realPath, err := filepath.EvalSymlinks(resolved); err == nil {
			resolved = realPath
		} else {
			resolved = filepath.Clean(resolved)
		}

		searchPaths = append(searchPaths, SearchPath{
			Raw:      raw,
			Resolved: resolved,
		})
	}

	return searchPaths
}
