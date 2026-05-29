package audit

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/masterwok/sohps/internal/elfparser"
)

// ensureTestBinaries runs the Makefile in testenv if the required binaries are missing.
func ensureTestBinaries(t *testing.T) {
	testenvDir := filepath.Join("..", "..", "testenv")
	binDir := filepath.Join(testenvDir, "bin")

	if _, err := os.Stat(filepath.Join(binDir, "test_appimage.AppImage")); os.IsNotExist(err) {
		t.Log("Building test binaries via testenv/Makefile...")
		cmd := exec.Command("make", "appimage")
		cmd.Dir = testenvDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Failed to build test binaries: %v\nOutput: %s", err, string(out))
		}
	}
}

func TestAuditAppImage(t *testing.T) {
	ensureTestBinaries(t)

	appImagePath := filepath.Join("..", "..", "testenv", "bin", "test_appimage.AppImage")
	if _, err := os.Stat(appImagePath); os.IsNotExist(err) {
		t.Skipf("Test binary %s not found. Skipping AppImage test.", appImagePath)
	}

	offset := elfparser.GetAppImageOffset(appImagePath)
	if offset == 0 {
		t.Fatalf("Failed to get offset for AppImage")
	}

	libs := []string{"libc.so.6"}
	candidates := AuditAppImage(appImagePath, offset, libs)

	if len(candidates) == 0 {
		t.Errorf("Expected AuditAppImage to find vulnerabilities in test_appimage.AppImage")
	} else {
		foundLD := false
		for _, c := range candidates {
			if c.IsEnvVar && c.Library == "LD_LIBRARY_PATH" {
				// We expect an Environment Poisoning candidate
				foundLD = true
			} else if !c.IsEnvVar && c.Category == "Environment Poisoning" {
				foundLD = true
			}
		}
		if !foundLD {
			t.Errorf("Expected to find LD_LIBRARY_PATH poisoning, found %v", candidates)
		}
	}
}
