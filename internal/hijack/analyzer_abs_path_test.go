package hijack

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckAbsPathLib_MissingLibInNonWritableDir(t *testing.T) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "testdir")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a non-writable sub-directory
	readOnlyDir := filepath.Join(tmpDir, "readonly")
	if err := os.Mkdir(readOnlyDir, 0555); err != nil {
		t.Fatalf("Failed to create read-only dir: %v", err)
	}

	// Define a library path within the read-only directory
	libPath := filepath.Join(readOnlyDir, "libtest.so")

	// Call the function under test
	candidate := checkAbsPathLib(libPath, "Direct", false, "/")

	// Assert that the candidate IS considered a hijack opportunity
	if !candidate.CanHijack {
		t.Errorf("Expected CanHijack to be true, but it was false")
	}

	// Assert that the action indicates the recreate strategy
	expectedAction := fmt.Sprintf("RECREATE: Writable parent (%s). Recreate full path and drop payload at: %s", tmpDir, libPath)
	if candidate.Action != expectedAction {
		t.Errorf("Expected action '%s', but got '%s'", expectedAction, candidate.Action)
	}
}
