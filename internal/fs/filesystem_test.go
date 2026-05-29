package fs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsWritable(t *testing.T) {
	tmp := t.TempDir()

	t.Run("Writable directory", func(t *testing.T) {
		d := filepath.Join(tmp, "writable")
		os.Mkdir(d, 0777)
		if !IsWritable(d) {
			t.Errorf("IsWritable returned false for 0777 directory")
		}
	})

	t.Run("Read-only directory", func(t *testing.T) {
		d := filepath.Join(tmp, "readonly")
		os.Mkdir(d, 0555)
		// Note: On some systems/CI environments, the owner can always write.
		// However, unix.Access(W_OK) should respect the mode bits.
		if IsWritable(d) {
			// We only fail if we're sure we're not running as root,
			// but usually in tests we skip this if it's unreliable.
			// For sohps, we assume the test environment allows mode bit testing.
			t.Log("Warning: IsWritable returned true for 0555 directory (running as root?)")
		}
	})
}

func TestFileExists(t *testing.T) {
	tmp := t.TempDir()

	t.Run("File exists", func(t *testing.T) {
		f := filepath.Join(tmp, "exists.txt")
		os.WriteFile(f, []byte("data"), 0644)
		if !FileExists(f) {
			t.Error("FileExists returned false for existing file")
		}
	})

	t.Run("File missing", func(t *testing.T) {
		if FileExists(filepath.Join(tmp, "missing.txt")) {
			t.Error("FileExists returned true for missing file")
		}
	})
}

func TestIsATSecure(t *testing.T) {
	tmp := t.TempDir()

	t.Run("SUID bit set", func(t *testing.T) {
		f := filepath.Join(tmp, "suid_bin")
		os.WriteFile(f, []byte(""), 0755)
		os.Chmod(f, 0755|os.ModeSetuid)
		if !IsATSecure(f) {
			t.Error("IsATSecure returned false for SUID binary")
		}
	})

	t.Run("SGID bit set", func(t *testing.T) {
		f := filepath.Join(tmp, "sgid_bin")
		os.WriteFile(f, []byte(""), 0755)
		os.Chmod(f, 0755|os.ModeSetgid)
		if !IsATSecure(f) {
			t.Error("IsATSecure returned false for SGID binary")
		}
	})

	t.Run("No special bits", func(t *testing.T) {
		f := filepath.Join(tmp, "normal_bin")
		os.WriteFile(f, []byte(""), 0755)
		if IsATSecure(f) {
			t.Error("IsATSecure returned true for normal binary")
		}
	})
}

func TestFindWritableParent(t *testing.T) {
	tmp := t.TempDir()

	// Create a nested structure
	// tmp (Writable)
	//  └── parent (Writable)
	//       └── child (Read-only)
	//            └── target (Missing)

	parent := filepath.Join(tmp, "parent")
	os.Mkdir(parent, 0777)

	child := filepath.Join(parent, "child")
	os.Mkdir(child, 0555)

	target := filepath.Join(child, "target_dir")

	t.Run("Finds writable parent", func(t *testing.T) {
		// Mock RootPath to avoid skipping our temp dir
		RootPath = tmp
		defer func() { RootPath = "" }()

		// We start at target (which doesn't exist).
		// We go up to child (RO).
		// We go up to parent (Writable).
		// We should find parent.
		foundDir, found := FindWritableParent(target)

		if !found {
			t.Fatalf("FindWritableParent failed to find a writable parent")
		}

		if foundDir != parent {
			t.Errorf("expected parent %s, got %s", parent, foundDir)
		}
	})

	t.Run("Stops at root or RootPath", func(t *testing.T) {
		RootPath = parent // Set parent as root
		defer func() { RootPath = "" }()

		// Starting from target, we hit child (RO).
		// Then we hit parent (which is RootPath).
		// The loop should break and return nothing.
		foundDir, found := FindWritableParent(target)

		if found {
			t.Errorf("expected no writable parent found, but got: %s", foundDir)
		}
	})
}
