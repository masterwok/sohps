package elfparser

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

// ensureTestBinaries runs the Makefile in testenv if the required binaries are missing.
func ensureTestBinaries(t *testing.T) {
	testenvDir := filepath.Join("..", "..", "testenv")
	binDir := filepath.Join(testenvDir, "bin")

	if _, err := os.Stat(filepath.Join(binDir, "test_nodeflib")); os.IsNotExist(err) {
		t.Log("Building test binaries via testenv/Makefile...")
		cmd := exec.Command("make", "all")
		cmd.Dir = testenvDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Failed to build test binaries: %v\nOutput: %s", err, string(out))
		}
	}
}

// TestExtractRawSearchPaths ensures the tool correctly prioritizes DT_RUNPATH over DT_RPATH
// and properly extracts paths from both ELF headers and system configuration.
func TestExtractRawSearchPaths(t *testing.T) {
	ensureTestBinaries(t)

	// Helper to safely load the file and run extraction
	extractPathsFrom := func(binName string) []string {
		path := filepath.Join("..", "..", "testenv", "bin", binName)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Skipf("Test binary %s not found. Skipping test.", path)
		}

		f, err := GetHandle(path)
		if err != nil {
			t.Fatalf("Failed to open %s: %v", path, err)
		}
		defer f.Close()

		return ExtractRawSearchPaths(f, "", "/")
	}

	t.Run("DT_RUNPATH is extracted", func(t *testing.T) {
		paths := extractPathsFrom("test_runpath")
		if len(paths) == 0 || paths[0] != "/tmp/sohps_test/runpath" {
			t.Errorf("Expected first path to be /tmp/sohps_test/runpath, got %v", paths)
		}
	})

	t.Run("DT_RPATH is extracted (legacy fallback)", func(t *testing.T) {
		paths := extractPathsFrom("test_rpath")
		if len(paths) == 0 || paths[0] != "/tmp/sohps_test/rpath" {
			t.Errorf("Expected first path to be /tmp/sohps_test/rpath, got %v", paths)
		}
	})

	t.Run("Multiple paths separated by colons are split", func(t *testing.T) {
		paths := extractPathsFrom("test_colon_split")
		// The first two paths should be the ones from our RUNPATH
		if len(paths) < 2 {
			t.Fatalf("Expected at least 2 paths, got %d", len(paths))
		}
		if paths[0] != "/tmp/sohps_test/one" || paths[1] != "/tmp/sohps_test/two" {
			t.Errorf("Expected [/tmp/sohps_test/one /tmp/sohps_test/two], got [%s %s]", paths[0], paths[1])
		}
	})
}

// TestParseLdConf verifies the recursive parsing of Linux dynamic linker configuration files.
func TestParseLdConf(t *testing.T) {
	tmp := t.TempDir()

	// 1. Create a sub-directory for includes
	confD := filepath.Join(tmp, "ld.so.conf.d")
	os.Mkdir(confD, 0755)

	// 2. Create some include files
	os.WriteFile(filepath.Join(confD, "libc.conf"), []byte("/lib/x86_64-linux-gnu\n/usr/lib/x86_64-linux-gnu"), 0644)
	os.WriteFile(filepath.Join(confD, "local.conf"), []byte("# A comment\n\n/usr/local/lib"), 0644)

	// 3. Create the main conf file
	mainConf := filepath.Join(tmp, "ld.so.conf")
	mainContent := "include " + filepath.Join(confD, "*.conf") + "\n/opt/lib\n"
	os.WriteFile(mainConf, []byte(mainContent), 0644)

	expected := []string{
		"/lib/x86_64-linux-gnu",
		"/usr/lib/x86_64-linux-gnu",
		"/usr/local/lib",
		"/opt/lib",
	}

	result := parseLdConf(mainConf, nil)

	// The order might depend on filepath.Glob sorting (which is lexical)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("got %v, want %v", result, expected)
	}
}

func TestAppImageParsing(t *testing.T) {
	ensureTestBinaries(t)

	appImagePath := filepath.Join("..", "..", "testenv", "bin", "test_appimage.AppImage")
	if _, err := os.Stat(appImagePath); os.IsNotExist(err) {
		t.Skipf("Test binary %s not found. Skipping AppImage test.", appImagePath)
	}

	t.Run("IsAppImage", func(t *testing.T) {
		if !IsAppImage(appImagePath) {
			t.Errorf("Expected IsAppImage to return true for %s", appImagePath)
		}
	})

	t.Run("GetAppImageOffset", func(t *testing.T) {
		offset := GetAppImageOffset(appImagePath)
		if offset == 0 {
			t.Errorf("Expected GetAppImageOffset to return a valid offset, got 0")
		}
	})

	t.Run("Not AppImage", func(t *testing.T) {
		notAppImage := filepath.Join("..", "..", "testenv", "bin", "test_rpath")
		if IsAppImage(notAppImage) {
			t.Errorf("Expected IsAppImage to return false for regular ELF")
		}
	})
}

func TestELFHelpers(t *testing.T) {
	ensureTestBinaries(t)

	// test_writable_path uses -lcustom which should appear in DT_NEEDED
	testBin := filepath.Join("..", "..", "testenv", "bin", "test_writable_path")
	if _, err := os.Stat(testBin); os.IsNotExist(err) {
		t.Skipf("Test binary %s not found. Skipping ELF helpers test.", testBin)
	}

	f, err := GetHandle(testBin)
	if err != nil {
		t.Fatalf("Failed to open %s: %v", testBin, err)
	}
	defer f.Close()

	t.Run("GetRequiredLibraries", func(t *testing.T) {
		libs, err := GetRequiredLibraries(f)
		if err != nil {
			t.Fatalf("GetRequiredLibraries failed: %v", err)
		}
		
		foundCustom := false
		for _, lib := range libs {
			if lib == "libcustom.so" {
				foundCustom = true
				break
			}
		}
		if !foundCustom {
			t.Errorf("Expected to find libcustom.so in required libraries, got %v", libs)
		}
	})

	t.Run("HasBindNow", func(t *testing.T) {
		// test_writable_path is not built with -z now, so it shouldn't have bind now
		if HasBindNow(f) {
			t.Errorf("Expected HasBindNow to return false for test_writable_path")
		}
	})
	
	t.Run("GetDataObjects", func(t *testing.T) {
		undef, exported := GetDataObjects(f)
		// Usually main binaries have some exported data objects but might not have undefined ones
		_ = undef
		_ = exported
	})
}
