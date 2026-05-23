package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsELF(t *testing.T) {
	tmp := t.TempDir()

	t.Run("Valid ELF header", func(t *testing.T) {
		f := filepath.Join(tmp, "valid.elf")
		os.WriteFile(f, []byte("\x7fELFsomething"), 0644)
		if !IsELF(f) {
			t.Error("IsELF returned false for valid ELF header")
		}
	})

	t.Run("Invalid header", func(t *testing.T) {
		f := filepath.Join(tmp, "invalid.txt")
		os.WriteFile(f, []byte("NOT AN ELF"), 0644)
		if IsELF(f) {
			t.Error("IsELF returned true for invalid header")
		}
	})

	t.Run("Empty file", func(t *testing.T) {
		f := filepath.Join(tmp, "empty.bin")
		os.WriteFile(f, []byte(""), 0644)
		if IsELF(f) {
			t.Error("IsELF returned true for empty file")
		}
	})

	t.Run("Missing file", func(t *testing.T) {
		if IsELF(filepath.Join(tmp, "nonexistent")) {
			t.Error("IsELF returned true for missing file")
		}
	})
}

func TestDiscoverBinaries(t *testing.T) {
	tmp := t.TempDir()

	// 1. Create a structure:
	// tmp/bin1.elf
	// tmp/subdir/bin2.elf
	// tmp/subdir/link_to_bin1 -> ../bin1.elf (Should be de-duplicated)
	// tmp/proc/bin3.elf (Should be ignored)
	
	bin1 := filepath.Join(tmp, "bin1.elf")
	os.WriteFile(bin1, []byte("\x7fELF1"), 0755)

	subdir := filepath.Join(tmp, "subdir")
	os.Mkdir(subdir, 0755)
	
	bin2 := filepath.Join(subdir, "bin2.elf")
	os.WriteFile(bin2, []byte("\x7fELF2"), 0755)

	link := filepath.Join(subdir, "link_to_bin1")
	os.Symlink(bin1, link)

	proc := filepath.Join(tmp, "proc")
	os.Mkdir(proc, 0755)
	bin3 := filepath.Join(proc, "bin3.elf")
	os.WriteFile(bin3, []byte("\x7fELF3"), 0755)

	results, err := DiscoverBinaries(tmp)
	if err != nil {
		t.Fatalf("DiscoverBinaries failed: %v", err)
	}

	// We expect bin1 and bin2. bin3 is in /proc (ignored). link_to_bin1 is bin1 (de-duplicated).
	// However, DiscoverBinaries returns the FIRST path it finds for a unique binary.
	// So it should return bin1 and bin2.
	
	if len(results) != 2 {
		t.Errorf("expected 2 binaries, got %d: %v", len(results), results)
	}

	foundBin1 := false
	foundBin2 := false
	for _, path := range results {
		if filepath.Base(path) == "bin1.elf" {
			foundBin1 = true
		}
		if filepath.Base(path) == "bin2.elf" {
			foundBin2 = true
		}
		if filepath.Base(path) == "bin3.elf" {
			t.Errorf("found bin3.elf in ignored directory /proc")
		}
	}

	if !foundBin1 || !foundBin2 {
		t.Errorf("did not find expected binaries. found: %v", results)
	}
}
