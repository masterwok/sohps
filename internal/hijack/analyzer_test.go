package hijack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/masterwok/sohps/internal/fs"
)

// TestEvaluateHijackVector tests the core vulnerability classification matrix.
// It uses real temporary directories and files to ensure permissions are handled accurately.
func TestEvaluateHijackVector(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(dir string) (target string, dirPath string, exists bool)
		wantHijack  bool
		wantAction  string // substring match
	}{
		{
			name: "Missing library in writable directory",
			setup: func(dir string) (string, string, bool) {
				d := filepath.Join(dir, "writable_dir")
				os.Mkdir(d, 0777)
				return filepath.Join(d, "lib.so"), d, false
			},
			wantHijack: true,
			wantAction: "DROP: Directory is writable",
		},
		{
			name: "Existing library in writable directory",
			setup: func(dir string) (string, string, bool) {
				d := filepath.Join(dir, "writable_dir_exists")
				os.Mkdir(d, 0777)
				f := filepath.Join(d, "lib.so")
				os.WriteFile(f, []byte("data"), 0644)
				return f, d, true
			},
			wantHijack: true,
			wantAction: "OVERWRITE: Delete existing library",
		},
		{
			name: "Writable file in read-only directory",
			setup: func(dir string) (string, string, bool) {
				d := filepath.Join(dir, "ro_dir")
				os.Mkdir(d, 0777) // Create as writable first
				f := filepath.Join(d, "lib.so")
				os.WriteFile(f, []byte("data"), 0666) // File is writable
				os.Chmod(d, 0555)                     // Directory is now RO
				return f, d, true
			},
			wantHijack: true,
			wantAction: "INJECT: Overwrite writable library file",
		},
		{
			name: "Safe: Missing library in read-only directory",
			setup: func(dir string) (string, string, bool) {
				d := filepath.Join(dir, "ro_dir_missing")
				os.Mkdir(d, 0555)
				return filepath.Join(d, "lib.so"), d, false
			},
			wantHijack: false,
		},
		{
			name: "Safe: Read-only library in read-only directory",
			setup: func(dir string) (string, string, bool) {
				d := filepath.Join(dir, "ro_dir_ro_file")
				os.Mkdir(d, 0777)
				f := filepath.Join(d, "lib.so")
				os.WriteFile(f, []byte("data"), 0444)
				os.Chmod(d, 0555)
				return f, d, true
			},
			wantHijack: false,
		},
		{
			name: "Missing library with writable parent directory",
			setup: func(dir string) (string, string, bool) {
				parent := filepath.Join(dir, "writable_parent_missing")
				child := filepath.Join(parent, "ro_child")
				os.MkdirAll(child, 0777) // Creates parent (777) and child (777)
				os.Chmod(child, 0555)    // Lock child, leaving parent writable
				return filepath.Join(child, "lib.so"), child, false
			},
			wantHijack: true,
			wantAction: "RECREATE: Writable parent",
		},
		{
			name: "Existing library with writable parent directory",
			setup: func(dir string) (string, string, bool) {
				parent := filepath.Join(dir, "writable_parent_exists")
				child := filepath.Join(parent, "ro_child")
				os.MkdirAll(child, 0777)
				f := filepath.Join(child, "lib.so")
				os.WriteFile(f, []byte("data"), 0444) // File RO
				os.Chmod(child, 0555)                 // Child RO, Parent remains writable
				return f, child, true
			},
			wantHijack: true,
			wantAction: "RECREATE: Rename writable parent",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			
			fs.TestRoot = tmp
			defer func() { fs.TestRoot = "" }()

			target, dir, exists := tc.setup(tmp)

			// Ensure directory is writable before teardown
			defer os.Chmod(dir, 0777)

			// Ensure parent directory is writable before teardown (for the new tests)
			defer os.Chmod(filepath.Dir(dir), 0777)

			canHijack, action := evaluateHijackVector(target, dir, exists)
			if canHijack != tc.wantHijack {
				t.Errorf("got canHijack = %v, want %v", canHijack, tc.wantHijack)
			}

			if tc.wantHijack && !strings.Contains(action, tc.wantAction) {
				t.Errorf("action %q did not contain %q", action, tc.wantAction)
			}
		})
	}
}

// TestBuildSearchPaths tests the expansion of linker macros and relative traversals.
// Accurate path resolution is critical for avoiding false negatives.
func TestBuildSearchPaths(t *testing.T) {
	targetBinary := "/opt/app/bin/target"
	expectedCWD, _ := filepath.Abs("")

	tests := []struct {
		name     string
		rawPaths []string
		expected []SearchPath
	}{
		{
			name:     "Expands $ORIGIN to binary directory",
			rawPaths: []string{"$ORIGIN/lib"},
			expected: []SearchPath{{Raw: "$ORIGIN/lib", Resolved: "/opt/app/bin/lib"}},
		},
		{
			name:     "Expands ${ORIGIN} to binary directory",
			rawPaths: []string{"${ORIGIN}/lib"},
			expected: []SearchPath{{Raw: "${ORIGIN}/lib", Resolved: "/opt/app/bin/lib"}},
		},
		{
			name:     "Expands $ORIGIN with parent traversal",
			rawPaths: []string{"$ORIGIN/../lib"},
			expected: []SearchPath{{Raw: "$ORIGIN/../lib", Resolved: "/opt/app/lib"}},
		},
		{
			name:     "Expands $ORIGIN in nested directory",
			rawPaths: []string{"$ORIGIN/.././../opt/lib"},
			expected: []SearchPath{{Raw: "$ORIGIN/.././../opt/lib", Resolved: "/opt/opt/lib"}},
		},
		{
			name:     "Resolves strictly relative paths to tool CWD",
			rawPaths: []string{"lib/"},
			expected: []SearchPath{{Raw: "lib/", Resolved: filepath.Join(expectedCWD, "lib")}},
		},
		{
			name:     "Handles empty RUNPATH",
			rawPaths: []string{""},
			expected: []SearchPath{{Raw: "Empty Path (Implicit CWD)", Resolved: "CWD_HIJACK_VECTOR"}},
		},
		{
			name:     "Expands $LIB and $PLATFORM based on architecture",
			rawPaths: []string{"/opt/app/$LIB/$PLATFORM"},
			expected: []SearchPath{{Raw: "/opt/app/$LIB/$PLATFORM", Resolved: "/opt/app/lib64/x86_64"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := buildSearchPaths(tc.rawPaths, targetBinary, false, "EM_X86_64")

			if len(result) != len(tc.expected) {				t.Fatalf("expected %d paths, got %d", len(tc.expected), len(result))
			}

			for i, path := range result {
				if path.Raw != tc.expected[i].Raw {
					t.Errorf("expected raw %q, got %q", tc.expected[i].Raw, path.Raw)
				}
				if path.Resolved != tc.expected[i].Resolved {
					t.Errorf("expected resolved %q, got %q", tc.expected[i].Resolved, path.Resolved)
				}
			}
		})
	}
}

// TestBuildSearchPathsATSecure ensures that SUID/SGID binaries filter untrusted paths.
func TestBuildSearchPathsATSecure(t *testing.T) {
	targetBinary := "/opt/app/bin/suid_target"

	rawPaths := []string{
		"$ORIGIN/lib",     // Should be DROPPED
		"lib/",            // Should be DROPPED
		"/opt/trusted/lib",// Should be KEPT
	}

	expected := []SearchPath{
		{Raw: "/opt/trusted/lib", Resolved: "/opt/trusted/lib"},
	}

	result := buildSearchPaths(rawPaths, targetBinary, true, "EM_X86_64")

	if len(result) != len(expected) {
		t.Fatalf("AT_SECURE filter failed: expected %d paths, got %d", len(expected), len(result))
	}

	if result[0].Raw != expected[0].Raw {
		t.Errorf("expected %q, got %q", expected[0].Raw, result[0].Raw)
	}
}

// TestCheckSearchPathLib tests the loop that walks the search path array.
// It must accurately mimic the linker's stop-at-first-match behavior.
func TestCheckSearchPathLib(t *testing.T) {
	tmp := t.TempDir()
	
	fs.TestRoot = tmp
	defer func() { fs.TestRoot = "" }()
	
	// Setup:
	// 1. /tmp/dir1 (Writable, No file)
	// 2. /tmp/dir2 (Read-only, Has file) -> Linker should stop here
	// 3. /tmp/dir3 (Writable, No file) -> Should NOT be flagged because linker stops at dir2
	dir1 := filepath.Join(tmp, "dir1")
	dir2 := filepath.Join(tmp, "dir2")
	dir3 := filepath.Join(tmp, "dir3")

	os.Mkdir(dir1, 0777)
	os.Mkdir(dir2, 0777)
	os.Mkdir(dir3, 0777)
	
	// Sandbox the TempDir so parent directory checks don't bleed into /tmp
	// We must do this AFTER creating the subdirectories, otherwise Mkdir fails!
	os.Chmod(tmp, 0555)
	defer os.Chmod(tmp, 0777)

	libName := "libtest.so"
	os.WriteFile(filepath.Join(dir2, libName), []byte("data"), 0444) // File must be RO to be safe
	os.Chmod(dir2, 0555) // Make dir2 RO so the file itself isn't hijackable
	defer os.Chmod(dir2, 0777) // Cleanup for TempDir

	searchPaths := []SearchPath{
		{Raw: "dir1", Resolved: dir1},
		{Raw: "dir2", Resolved: dir2},
		{Raw: "dir3", Resolved: dir3},
	}

	candidates := checkSearchPathLib(searchPaths, libName, "EM_X86_64")

	// We expect exactly ONE candidate now because we fixed the HWCAP alert flood.
	// The tool should only report the highest-priority HWCAP subdir for dir1.
	// dir2 has the file but is RO, so no hijack there.
	// dir3 is writable but should be ignored because the linker stops at dir2.
	if len(candidates) != 1 {
		t.Logf("Found %d candidates:", len(candidates))
		for _, c := range candidates {
			t.Logf(" - %s (Action: %s)", c.ResolvedDir, c.Action)
		}
		t.Fatalf("expected 1 hijack candidate, got %d", len(candidates))
	}

	// Make sure dir3 is NOT flagged
	for _, c := range candidates {
		if strings.Contains(c.ResolvedDir, dir3) {
			t.Errorf("FAIL: flagged %s, but linker should have stopped at %s", c.ResolvedDir, dir2)
		}
	}
}
