package scanner

import (
	"os"
	"path/filepath"
	"strings"
)

// DiscoverBinaries walks the target directory and returns a slice of unique ELF binary paths.
func DiscoverBinaries(targetPath string) ([]string, error) {
	var targetFiles []string
	seen := make(map[string]bool)

	err := filepath.WalkDir(targetPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		// Prune virtual and irrelevant directories to speed up root scans
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".") ||
				name == "proc" || name == "sys" || name == "dev" || name == "run" || name == "snap" {
				return filepath.SkipDir
			}
			return nil
		}

		if IsELF(path) {
			realPath, err := filepath.EvalSymlinks(path)
			if err != nil {
				realPath = path
			}
			absPath, err := filepath.Abs(realPath)
			if err == nil {
				realPath = absPath
			}

			if seen[realPath] {
				return nil
			}
			seen[realPath] = true
			targetFiles = append(targetFiles, path)
		}
		return nil
	})

	return targetFiles, err
}

// IsELF performs a quick check for the ELF magic header.
func IsELF(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	header := make([]byte, 4)
	if n, err := f.Read(header); err != nil || n < 4 {
		return false
	}

	return header[0] == 0x7f && string(header[1:4]) == "ELF"
}
