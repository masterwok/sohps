package report

import (
	"testing"

	"github.com/masterwok/sohps/internal/hijack"
)

func TestInit(t *testing.T) {
	t.Run("NoColor disables ANSI codes", func(t *testing.T) {
		Init(false, true)
		if Reset != "" || Red != "" {
			t.Errorf("Init(true) failed to clear color codes. Reset=%q, Red=%q", Reset, Red)
		}
	})

	t.Run("Color enabled by default", func(t *testing.T) {
		Init(false, false)
		if Reset == "" || Red == "" {
			t.Error("Init(false) incorrectly cleared color codes")
		}
	})
}

func TestPrintFindingsSmoke(t *testing.T) {
	// Simple smoke test to ensure no panics with empty or populated candidates
	Init(false, true)

	t.Run("Empty candidates", func(t *testing.T) {
		PrintFindings([]*hijack.HijackCandidate{})
	})

	t.Run("Populated candidates", func(t *testing.T) {
		candidates := []*hijack.HijackCandidate{
			{
				Library:     "libc.so.6",
				Category:    "Implicit CWD",
				RawRunPath:  "",
				ResolvedDir: "CWD",
				CanHijack:   true,
				Action:      "Test Action",
			},
		}
		PrintFindings(candidates)
	})
}
