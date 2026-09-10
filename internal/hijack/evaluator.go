package hijack

import (
	"fmt"

	"github.com/masterwok/sohps/internal/fs"
)

// evaluateHijackVector routes the vulnerability check to the appropriate
// specialized function based on file existence, adhering to SRP.
func evaluateHijackVector(targetPath, dirPath, root string, fileExists bool) (bool, string) {
	if fileExists {
		return evaluateExistingFileVector(targetPath, dirPath, root)
	}
	return evaluateMissingFileVector(targetPath, dirPath, root)
}

// evaluateExistingFileVector determines hijack strategies when the target library already exists.
func evaluateExistingFileVector(targetPath, dirPath, root string) (bool, string) {
	// 1. Immediate directory is writable (Replacement)
	if fs.IsWritable(dirPath) {
		action := fmt.Sprintf("OVERWRITE: Delete existing library and replace with payload: rm %s && mv payload.so %s", targetPath, targetPath)
		return true, action
	}

	// 2. Parent directory is writable (Path Hijack via tree recreation)
	if parentDir, found := fs.FindWritableParent(dirPath, root); found {
		action := fmt.Sprintf("RECREATE: Rename writable parent (%s) and recreate path to drop payload: mv %s <backup> && mkdir -p %s", parentDir, dirPath, dirPath)
		return true, action
	}

	// 3. File itself is writable, but directory tree is locked (Injection)
	if fs.IsWritable(targetPath) {
		action := fmt.Sprintf("INJECT: Overwrite writable library file directly (may trigger ETXTBSY if active): cp payload.so %s", targetPath)
		return true, action
	}

	return false, ""
}

// evaluateMissingFileVector determines hijack strategies when the target library is missing.
func evaluateMissingFileVector(targetPath, dirPath, root string) (bool, string) {
	// 1. Immediate directory is writable (Payload Drop)
	if fs.IsWritable(dirPath) {
		action := fmt.Sprintf("DROP: Directory is writable. Drop payload at: %s", targetPath)
		return true, action
	}

	// 2. Parent directory is writable (Path Hijack via tree recreation)
	if parentDir, found := fs.FindWritableParent(dirPath, root); found {
		action := fmt.Sprintf("RECREATE: Writable parent (%s). Recreate full path and drop payload at: %s", parentDir, targetPath)
		return true, action
	}

	return false, "SAFE: Library is missing, but directory is not writable."
}
