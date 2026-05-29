// Package elfparser provides safe extraction routines for analyzing Executable and Linkable Format (ELF) binaries.
package elfparser

import (
	"debug/elf"
	"fmt"
	"os"
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

// GetVersionedDependencies returns a list of library names from which this ELF file
// explicitly requests versioned symbols.
func GetVersionedDependencies(f *elf.File) []string {
	var versioned []string
	syms, err := f.ImportedSymbols()
	if err != nil {
		return versioned
	}

	reqLibs := make(map[string]bool)
	for _, s := range syms {
		if s.Version != "" && s.Library != "" {
			reqLibs[s.Library] = true
		}
	}

	for l := range reqLibs {
		versioned = append(versioned, l)
	}
	return versioned
}

// HasBindNow checks if the ELF file requires immediate binding (DF_BIND_NOW or DF_1_NOW).
func HasBindNow(f *elf.File) bool {
	// Check DT_FLAGS
	if flags, err := f.DynValue(elf.DT_FLAGS); err == nil {
		for _, flag := range flags {
			if flag&uint64(elf.DF_BIND_NOW) != 0 {
				return true
			}
		}
	}

	// Check DT_FLAGS_1
	if flags1, err := f.DynValue(elf.DT_FLAGS_1); err == nil {
		for _, flag := range flags1 {
			if flag&uint64(elf.DF_1_NOW) != 0 {
				return true
			}
		}
	}

	return false
}

// GetDataObjects extracts undefined and exported data object symbols from the ELF file.
// Data objects (STT_OBJECT) are resolved eagerly at load-time by the dynamic linker.
func GetDataObjects(f *elf.File) (undef []string, exported []string) {
	syms, err := f.DynamicSymbols()
	if err != nil {
		return
	}

	for _, s := range syms {
		if elf.ST_TYPE(s.Info) == elf.STT_OBJECT && s.Name != "" {
			if s.Section == elf.SHN_UNDEF {
				undef = append(undef, s.Name)
			} else {
				exported = append(exported, s.Name)
			}
		}
	}
	return
}


// ResolveTransitiveDependencies recursively finds all libraries required by the binary.
// It returns a map of library name to its resolved absolute path on the system,
// and a map indicating if a library requires a proxy (has versioned symbols requested from it, or is loaded by a parent enforcing BIND_NOW).
func ResolveTransitiveDependencies(path string, initialLibs []string, extraSearchPaths []string, ldLibraryPath string, root string) (map[string]string, map[string]bool, error) {
	f, err := GetHandle(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	proxyReqMap := make(map[string]bool)
	for _, l := range GetVersionedDependencies(f) {
		proxyReqMap[l] = true
	}

	isBindNow := HasBindNow(f)
	if isBindNow {
		for _, l := range initialLibs {
			proxyReqMap[l] = true
		}
	}

	globalUndefObjects := make(map[string]bool)
	libExportedObjects := make(map[string][]string)

	undefObjs, expObjs := GetDataObjects(f)
	for _, obj := range undefObjs {
		globalUndefObjects[obj] = true
	}
	// The main binary exports objects too, but usually it's the requester, not the provider.
	libExportedObjects[filepath.Base(path)] = expObjs

	if len(initialLibs) == 0 {
		initialLibs, err = GetRequiredLibraries(f)
		if err != nil {
			return nil, nil, err
		}
	}

	allLibs := make(map[string]string)
	for _, lib := range initialLibs {
		allLibs[lib] = "" // Path initially unknown
	}

	// Initial search paths from the main binary
	searchPaths := ExtractRawSearchPaths(f, ldLibraryPath, root)
	
	// Add extra search paths at the beginning
	searchPaths = append(extraSearchPaths, searchPaths...)

	// To resolve paths like $ORIGIN, we need the binary's directory
	binDir := filepath.Dir(path)

	processed := make(map[string]bool)
	queue := []string{}
	for _, lib := range initialLibs {
		if !strings.Contains(lib, "/") {
			queue = append(queue, lib)
		}
	}

	for len(queue) > 0 {
		libName := queue[0]
		queue = queue[1:]

		if processed[libName] {
			continue
		}
		processed[libName] = true

		// Find the library on disk
		resolvedPath := findLibrary(libName, searchPaths, binDir, root)
		if resolvedPath == "" {
			continue
		}

		allLibs[libName] = resolvedPath

		// Parse this library for more dependencies
		libF, err := GetHandle(resolvedPath)
		if err != nil {
			continue
		}
		
		subLibs, err := GetRequiredLibraries(libF)
		
		parentIsBindNow := HasBindNow(libF)
		
		for _, l := range GetVersionedDependencies(libF) {
			proxyReqMap[l] = true
		}

		if parentIsBindNow {
			for _, l := range subLibs {
				proxyReqMap[l] = true
			}
		}

		undefObjs, expObjs := GetDataObjects(libF)
		for _, obj := range undefObjs {
			globalUndefObjects[obj] = true
		}
		libExportedObjects[libName] = expObjs

		libF.Close()
		if err != nil {
			continue
		}

		for _, subLib := range subLibs {
			if _, exists := allLibs[subLib]; !exists {
				allLibs[subLib] = ""
				if !strings.Contains(subLib, "/") {
					queue = append(queue, subLib)
				}
			}
		}
	}

	// Data Object Check: If any library exports a data object that is required (undefined)
	// by another library in the graph, it MUST be proxy required, because data objects
	// are resolved eagerly at load-time regardless of BIND_NOW.
	for libName, exported := range libExportedObjects {
		for _, obj := range exported {
			if globalUndefObjects[obj] {
				proxyReqMap[libName] = true
				break
			}
		}
	}

	return allLibs, proxyReqMap, nil
}

func findLibrary(libName string, rawPaths []string, binDir string, root string) string {
	for _, raw := range rawPaths {
		// Expand $ORIGIN etc
		resolved := raw
		resolved = strings.ReplaceAll(resolved, "$ORIGIN", binDir)
		resolved = strings.ReplaceAll(resolved, "${ORIGIN}", binDir)
		
		// If it's an empty path, it's CWD
		if resolved == "" {
			resolved = "."
		}

		if !filepath.IsAbs(resolved) {
			abs, err := filepath.Abs(resolved)
			if err == nil {
				resolved = abs
			}
		}

		fullPath := filepath.Join(resolved, libName)
		if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
			return fullPath
		}
	}
	return ""
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
			if rp == "" {
				continue
			}
			searchPaths = append(searchPaths, strings.Split(rp, ":")...)
		}
	} else if rpaths, err := f.DynString(elf.DT_RPATH); err == nil && len(rpaths) > 0 {
		for _, rp := range rpaths {
			if rp == "" {
				continue
			}
			searchPaths = append(searchPaths, strings.Split(rp, ":")...)
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


// IsAppImage checks if the file is an AppImage Type 2 (contains AI\x02 at offset 8).
func IsAppImage(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	magic := make([]byte, 3)
	if _, err := f.ReadAt(magic, 8); err != nil {
		return false
	}

	return string(magic) == "AI\x02"
}

// GetAppImageOffset returns the offset of the embedded SquashFS image in an AppImage.
// For Type 2, it is usually appended after the ELF runtime (including section headers).
func GetAppImageOffset(path string) int64 {
	f, err := elf.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	// The SquashFS is typically appended after the section headers.
	// Section headers start at f.FileHeader.Shoff
	// There are f.FileHeader.Shnum of them
	// Each is f.FileHeader.Shentsize large
	
	// We'll use the reflection-free way to get these if possible, 
	// but elf.File already has these in its header.
	
	// For ELF64:
	// Shoff is at offset 40, 8 bytes
	// Shentsize is at offset 58, 2 bytes
	// Shnum is at offset 60, 2 bytes
	
	// However, elf.Open already parsed these. 
	// We can't access them directly from elf.File easily because they are private 
	// or part of the internal FileHeader.
	
	// Let's use a more robust way: find the maximum offset of any section.
	var maxOffset int64
	for _, sec := range f.Sections {
		end := int64(sec.Offset + sec.Size)
		if end > maxOffset {
			maxOffset = end
		}
	}
	
	// Also account for the section header table itself, which usually follows the sections.
	// We'll read the ELF header manually to get the exact end of the ELF.
	
	file, err := os.Open(path)
	if err != nil {
		return maxOffset
	}
	defer file.Close()
	
	// Read ELF64 header (64 bytes)
	header := make([]byte, 64)
	if _, err := file.ReadAt(header, 0); err != nil {
		return maxOffset
	}
	
	shoff := int64(0)
	shentsize := int(0)
	shnum := int(0)
	
	// We assume ELF64 for now as most AppImages are 64-bit
	// [40-47] e_shoff
	// [58-59] e_shentsize
	// [60-61] e_shnum
	
	// Check if it's 64-bit
	if header[4] == 2 {
		shoff = int64(header[40]) | int64(header[41])<<8 | int64(header[42])<<16 | int64(header[43])<<24 |
			int64(header[44])<<32 | int64(header[45])<<40 | int64(header[46])<<48 | int64(header[47])<<56
		shentsize = int(header[58]) | int(header[59])<<8
		shnum = int(header[60]) | int(header[61])<<8
	} else {
		// ELF32
		shoff = int64(header[32]) | int64(header[33])<<8 | int64(header[34])<<16 | int64(header[35])<<24
		shentsize = int(header[46]) | int(header[47])<<8
		shnum = int(header[48]) | int(header[49])<<8
	}
	
	tableEnd := shoff + int64(shnum*shentsize)
	if tableEnd > maxOffset {
		maxOffset = tableEnd
	}

	return maxOffset
}

