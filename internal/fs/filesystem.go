// Package fs contains a collection of filesystem helper funcs.
package fs

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// IsWritable uses the unix.Access syscall to accurately check if the current user
// (or effective user) has write permissions to a given directory.
func IsWritable(dir string) bool {
	err := unix.Access(dir, unix.W_OK)
	return err == nil
}

// FileExists checks to see if a file exists.
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsATSecure returns true if the file has SUID or SGID bits set.
// This indicates the kernel will execute the binary with AT_SECURE enabled.
func IsATSecure(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	
	mode := info.Mode()
	return mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0
}

var RootPath string

// FindWritableParent walks up the directory tree from the given path.
// It returns the first directory that is writable, or an empty string if none are found.
// It stops when it reaches the root directory or the configured RootPath.
func FindWritableParent(targetPath string) (string, bool) {
	dir := targetPath

	for {
		parent := filepath.Dir(dir)
		
		// If filepath.Dir returns the same path, we've hit the root (e.g., "/")
		if parent == dir {
			break
		}
		
		// Do not evaluate the configured root itself (or anything above it) as a writable parent.
		if RootPath != "" && RootPath != "/" && len(parent) <= len(RootPath) {
			break
		}

		if IsWritable(parent) {
			return parent, true
		}

		dir = parent
	}

	return "", false
}
