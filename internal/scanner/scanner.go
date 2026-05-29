package scanner

import (
	"os"
	"path/filepath"
	"strings"
)

// DiscoverBinaries walks the target directory and returns a slice of unique ELF binary paths.
func DiscoverBinaries(targetPath string, root string) ([]string, error) {
	var targetFiles []string
	seen := make(map[string]bool)

	err := filepath.WalkDir(targetPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		// Prune virtual and irrelevant directories to speed up root scans.
		if d.IsDir() {
			name := d.Name()

			// 1. Skip specifically excluded system directories if they are at the root.
			// We check both absolute path and ensure it's at the top level of the configured root.
			abs, _ := filepath.Abs(path)

			// Virtual directories to prune
			pruneDirs := []string{"/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/lxcfs"}

			for _, p := range pruneDirs {
				// Match either the system path or the rootfs-prefixed path
				if abs == p || abs == filepath.Join(root, p) {
					return filepath.SkipDir
				}
			}

			// 2. Skip temporary directories created by the tool itself
			if strings.HasPrefix(name, "sohps_appimage_") {
				return filepath.SkipDir
			}

			// 3. Skip hidden directories (e.g., .git) unless the scan started there
			if strings.HasPrefix(name, ".") && path != targetPath {
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
