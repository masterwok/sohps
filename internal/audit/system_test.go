package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckSystemPreload(t *testing.T) {
	tmp := t.TempDir()

	t.Run("Writable preload file", func(t *testing.T) {
		etcDir := filepath.Join(tmp, "etc")
		os.Mkdir(etcDir, 0777)
		preloadPath := filepath.Join(etcDir, "ld.so.preload")
		os.WriteFile(preloadPath, []byte(""), 0666) // Writable

		candidates := CheckSystemPreload(tmp)

		if len(candidates) == 0 {
			t.Fatal("expected 1 candidate, got 0")
		}
		if candidates[0].Category != "System Preload" {
			t.Errorf("expected System Preload category, got: %s", candidates[0].Category)
		}
		if !strings.Contains(candidates[0].Action, "PRELOAD INJECT") {
			t.Errorf("expected PRELOAD INJECT action, got: %s", candidates[0].Action)
		}
	})

	t.Run("Missing preload in writable etc", func(t *testing.T) {
		etcDir := filepath.Join(tmp, "etc_writable")
		os.Mkdir(etcDir, 0777)

		// Create a dummy root directory to pass to CheckSystemPreload
		dummyRoot := filepath.Join(tmp, "dummy_root")
		os.Mkdir(dummyRoot, 0777)
		// Create the etc directory inside the dummy root
		os.Mkdir(filepath.Join(dummyRoot, "etc"), 0777)

		candidates := CheckSystemPreload(dummyRoot)

		if len(candidates) == 0 {
			t.Fatal("expected 1 candidate, got 0")
		}
		if candidates[0].Category != "System Preload" {
			t.Errorf("expected System Preload category, got: %s", candidates[0].Category)
		}
		if !strings.Contains(candidates[0].Action, "PRELOAD CREATE") {
			t.Errorf("expected PRELOAD CREATE action, got: %s", candidates[0].Action)
		}
	})

	t.Run("Safe configuration", func(t *testing.T) {
		safeRoot := filepath.Join(t.TempDir(), "safe_root")
		safeEtc := filepath.Join(safeRoot, "etc")
		os.MkdirAll(safeEtc, 0555) // Read-only etc
		preloadPath := filepath.Join(safeEtc, "ld.so.preload")
		os.WriteFile(preloadPath, []byte(""), 0444) // Read-only file

		candidates := CheckSystemPreload(safeRoot)

		if len(candidates) != 0 {
			t.Errorf("expected no candidates for safe configuration, got: %d", len(candidates))
		}
	})
}

func TestRunPreloadAudit(t *testing.T) {
	tmp := t.TempDir()

	t.Run("Writable preload file", func(t *testing.T) {
		preloadPath := filepath.Join(tmp, "ld.so.preload")
		os.WriteFile(preloadPath, []byte(""), 0666) // Writable

		candidates := RunPreloadAudit(preloadPath, tmp)

		if len(candidates) == 0 {
			t.Fatal("expected 1 candidate, got 0")
		}
		if candidates[0].Category != "System Preload" {
			t.Errorf("expected System Preload category, got: %s", candidates[0].Category)
		}
		if !strings.Contains(candidates[0].Action, "PRELOAD INJECT") {
			t.Errorf("expected PRELOAD INJECT action, got: %s", candidates[0].Action)
		}
	})

	t.Run("Missing preload in writable etc", func(t *testing.T) {
		preloadPath := filepath.Join(tmp, "nonexistent")
		// tmp is writable by default

		candidates := RunPreloadAudit(preloadPath, tmp)

		if len(candidates) == 0 {
			t.Fatal("expected 1 candidate, got 0")
		}
		if candidates[0].Category != "System Preload" {
			t.Errorf("expected System Preload category, got: %s", candidates[0].Category)
		}
		if !strings.Contains(candidates[0].Action, "PRELOAD CREATE") {
			t.Errorf("expected PRELOAD CREATE action, got: %s", candidates[0].Action)
		}
	})

	t.Run("Safe configuration", func(t *testing.T) {
		safeDir := filepath.Join(tmp, "safe_etc")
		os.Mkdir(safeDir, 0555) // Read-only etc
		preloadPath := filepath.Join(safeDir, "ld.so.preload")
		os.WriteFile(preloadPath, []byte(""), 0444) // Read-only file

		candidates := RunPreloadAudit(preloadPath, safeDir)

		if len(candidates) != 0 {
			t.Errorf("expected no candidates for safe configuration, got: %d", len(candidates))
		}
	})
}
