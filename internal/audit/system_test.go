package audit

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPreloadAudit(t *testing.T) {
	// Capture stdout
	old := os.Stdout

	capture := func(f func()) string {
		r, w, _ := os.Pipe()
		os.Stdout = w
		f()
		w.Close()
		os.Stdout = old
		var buf bytes.Buffer
		io.Copy(&buf, r)
		return buf.String()
	}

	tmp := t.TempDir()

	t.Run("Writable preload file", func(t *testing.T) {
		preloadPath := filepath.Join(tmp, "ld.so.preload")
		os.WriteFile(preloadPath, []byte(""), 0666) // Writable

		output := capture(func() {
			RunPreloadAudit(preloadPath, tmp)
		})

		if !strings.Contains(output, "[!] System Preload") {
			t.Errorf("expected System Preload tag, got: %s", output)
		}
		if !strings.Contains(output, "PRELOAD INJECT") {
			t.Errorf("expected PRELOAD INJECT action, got: %s", output)
		}
	})

	t.Run("Missing preload in writable etc", func(t *testing.T) {
		preloadPath := filepath.Join(tmp, "nonexistent")
		// tmp is writable by default

		output := capture(func() {
			RunPreloadAudit(preloadPath, tmp)
		})

		if !strings.Contains(output, "[!] System Preload") {
			t.Errorf("expected System Preload tag, got: %s", output)
		}
		if !strings.Contains(output, "PRELOAD CREATE") {
			t.Errorf("expected PRELOAD CREATE action, got: %s", output)
		}
	})

	t.Run("Safe configuration", func(t *testing.T) {
		safeDir := filepath.Join(tmp, "safe_etc")
		os.Mkdir(safeDir, 0555) // Read-only etc
		preloadPath := filepath.Join(safeDir, "ld.so.preload")
		os.WriteFile(preloadPath, []byte(""), 0444) // Read-only file

		output := capture(func() {
			RunPreloadAudit(preloadPath, safeDir)
		})

		if output != "" {
			t.Errorf("expected no output for safe configuration, got: %s", output)
		}
	})
}
