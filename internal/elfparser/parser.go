// Package elfparser provides safe extraction routines for analyzing Executable and Linkable Format (ELF) binaries.
package elfparser

import (
	"debug/elf"
	"fmt"
	"path/filepath"
	"strings"
)

// GetRequiredLibraries extracts the DT_NEEDED entries from an ELF binary.
// These entries represent the shared libraries explicitly required by the binary to execute.
func GetRequiredLibraries(f *elf.File) ([]string, error) {
	libs, err := f.ImportedLibraries()
	if err != nil {
		// Wrap the error with context and send it back to the caller
		return nil, fmt.Errorf("failed to read DT_NEEDED: %w", err)
	}

	// Also extract DT_AUDIT and DT_DEPAUDIT, as these are loaded by ld.so 
	// before execution and are subject to the same hijack vectors.
	if audits, err := f.DynString(elf.DynTag(0x7ffffffc)); err == nil {
		libs = append(libs, audits...)
	}
	if depaudits, err := f.DynString(elf.DynTag(0x7ffffffb)); err == nil {
		libs = append(libs, depaudits...)
	}

	return libs, nil
}

// GetHandle safely opens an ELF binary and returns the file descriptor.
func GetHandle(targetPath string) (*elf.File, error) {
	f, err := elf.Open(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open target binary: %w", err)
	}
	return f, nil
}

// ExtractRawSearchPaths extracts dynamic library search paths from an ELF binary.
// It prioritizes DT_RUNPATH over DT_RPATH, and injects LD_LIBRARY_PATH context if provided.
func ExtractRawSearchPaths(f *elf.File, ldLibraryPath string, root string) []string {
	var searchPaths []string
	hasRunpath := false

	// 1. Extract DT_RUNPATH or DT_RPATH
	if runpaths, err := f.DynString(elf.DT_RUNPATH); err == nil && len(runpaths) > 0 {
		hasRunpath = true
		for _, rp := range runpaths {
			if rp != "" {
				searchPaths = append(searchPaths, strings.Split(rp, ":")...)
			}
		}
	} else if rpaths, err := f.DynString(elf.DT_RPATH); err == nil && len(rpaths) > 0 {
		for _, rp := range rpaths {
			if rp != "" {
				searchPaths = append(searchPaths, strings.Split(rp, ":")...)
			}
		}
	}

	// 2. Inject LD_LIBRARY_PATH context
	// Precedence: RPATH -> LD_LIBRARY_PATH -> RUNPATH
	if ldLibraryPath != "" {
		ldPaths := strings.Split(ldLibraryPath, ":")
		if hasRunpath {
			// If RUNPATH exists, LD_LIBRARY_PATH comes before it.
			// Prepend it to the searchPaths slice.
			searchPaths = append(ldPaths, searchPaths...)
		} else {
			// If only RPATH exists (or neither), LD_LIBRARY_PATH comes after RPATH.
			searchPaths = append(searchPaths, ldPaths...)
		}
	}

	// 3. Check if DT_FLAGS_1 contains DF_1_NODEFLIB
	// If set, ld.so ignores default system paths for this binary.
	if flags1, err := f.DynValue(elf.DT_FLAGS_1); err == nil && len(flags1) > 0 {
		for _, flag := range flags1 {
			if flag&uint64(elf.DF_1_NODEFLIB) != 0 {
				return searchPaths
			}
		}
	}

	// 4. Dynamically build system fallback paths based on the target machine's config
	// Note: ld.so checks ld.so.conf paths BEFORE the hardcoded system defaults!
	systemPaths := parseLdConf(filepath.Join(root, "etc", "ld.so.conf"), nil)

	// Determine architecture-specific system defaults
	var defaults []string
	switch f.Machine {
	case elf.EM_X86_64, elf.EM_AARCH64:
		defaults = []string{"/lib64", "/usr/lib64", "/lib", "/usr/lib"}
	default:
		defaults = []string{"/lib", "/usr/lib"}
	}

	for _, d := range defaults {
		systemPaths = append(systemPaths, filepath.Join(root, d))
	}

	return append(searchPaths, systemPaths...)
}

