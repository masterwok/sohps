// Package sohps is the library entrypoint for the shared-object hijack path
// scanner. The CLI in cmd/sohps is a thin wrapper around this package - all
// the actual analysis lives in the internal packages this wraps.
package sohps

import (
	"context"
	"fmt"

	"github.com/masterwok/sohps/internal/audit"
	"github.com/masterwok/sohps/internal/elfparser"
	"github.com/masterwok/sohps/internal/fs"
	"github.com/masterwok/sohps/internal/hijack"
	"github.com/masterwok/sohps/internal/scanner"
)

// Finding is a verified privilege escalation path via shared object
// hijacking, or another sohps vulnerability class (System Preload,
// Environment Poisoning, etc).
type Finding = hijack.HijackCandidate

// Options configures a Scan/ScanTree call.
type Options struct {
	// LDLibraryPath simulates the LD_LIBRARY_PATH environment variable
	// (colon-separated) that would be in effect when the binary runs.
	LDLibraryPath string
}

// ScanTree walks targetDir for ELF binaries and AppImages and returns every
// verified hijack candidate found across all of them, plus a system-wide
// ld.so.preload check rooted at root.
//
// root is the filesystem root used to resolve system-wide linker search
// paths (ld.so.conf, default lib dirs, etc) and the global ld.so.preload
// check - the same role the CLI's --root flag plays. It's deliberately a
// separate parameter from targetDir: targetDir is only where binaries are
// discovered from, and $ORIGIN-relative paths always resolve against a
// binary's own location regardless of root, so the two don't have to be the
// same directory. Passing "/" here checks against the real host's actual
// system directories rather than targetDir's own - the right choice when
// targetDir is an extracted, scanner-owned package tree rather than a live
// system, since checking a self-owned directory's writability doesn't tell
// you anything about whether a properly-permissioned install would be
// vulnerable.
//
// ScanTree makes no use of package-level state and is safe to call
// concurrently for different targetDir/root values from multiple goroutines.
func ScanTree(ctx context.Context, targetDir, root string, opts Options) ([]*Finding, error) {
	findings := filterHijackable(audit.CheckSystemPreload(root))

	targetFiles, err := scanner.DiscoverBinaries(targetDir, root)
	if err != nil {
		return nil, fmt.Errorf("discover binaries: %w", err)
	}

	for _, path := range targetFiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		findings = append(findings, Scan(path, root, opts)...)
	}

	return findings, nil
}

// Scan analyzes a single ELF binary or AppImage and returns every verified
// hijack candidate found. root is used the same way as in ScanTree - pass
// the same root an enclosing ScanTree call would use.
func Scan(path, root string, opts Options) []*Finding {
	var candidates []*Finding

	f, err := elfparser.GetHandle(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	directLibs, err := elfparser.GetRequiredLibraries(f)
	if err != nil {
		directLibs = []string{}
	}

	allLibsMap, proxyReqMap, err := elfparser.ResolveTransitiveDependencies(path, directLibs, nil, opts.LDLibraryPath, root)
	if err != nil {
		allLibsMap = make(map[string]string)
		for _, l := range directLibs {
			allLibsMap[l] = ""
		}
		proxyReqMap = make(map[string]bool)
	}

	directMap := make(map[string]bool)
	for _, l := range directLibs {
		directMap[l] = true
	}

	var transitiveLibs []string
	for l := range allLibsMap {
		if !directMap[l] {
			transitiveLibs = append(transitiveLibs, l)
		}
	}

	if elfparser.IsAppImage(path) {
		if offset := elfparser.GetAppImageOffset(path); offset > 0 {
			var allLibsList []string
			for l := range allLibsMap {
				allLibsList = append(allLibsList, l)
			}
			candidates = append(candidates, audit.AuditAppImage(path, offset, allLibsList)...)
		}
	}

	rawPaths := elfparser.ExtractRawSearchPaths(f, opts.LDLibraryPath, root)
	hijackSearchPaths := hijack.BuildSearchPaths(rawPaths, path, fs.IsATSecure(path), f.Machine.String(), root)

	candidates = append(candidates, hijack.Analyze(hijackSearchPaths, directLibs, transitiveLibs, proxyReqMap, path, f.Machine.String(), root)...)

	return filterHijackable(candidates)
}

// filterHijackable drops candidates that were evaluated and found not
// actually exploitable. hijack.Analyze already does this for most paths
// internally, but checkAbsPathLib (absolute DT_NEEDED entries) can still
// return a non-hijackable candidate, and library callers shouldn't have to
// know that detail to get a clean result set - this mirrors what the CLI's
// report.PrintFindings already filters at display time.
func filterHijackable(candidates []*Finding) []*Finding {
	var hijackable []*Finding
	for _, c := range candidates {
		if c.CanHijack {
			hijackable = append(hijackable, c)
		}
	}
	return hijackable
}
