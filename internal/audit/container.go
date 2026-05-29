package audit

import (
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/masterwok/sohps/internal/elfparser"
	"github.com/masterwok/sohps/internal/hijack"
)

// AuditAppImage performs a security audit on an AppImage's internal configuration.
func AuditAppImage(path string, offset int64, libs []string) []*hijack.HijackCandidate {
	tmpDir, err := os.MkdirTemp("", "sohps_appimage_*")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(tmpDir)

	// Extract the entire SquashFS to find all binaries
	cmd := exec.Command("unsquashfs", "-offset", fmt.Sprintf("%d", offset), "-dest", tmpDir, path)
	if err := cmd.Run(); err != nil {
		return nil
	}

	appRunPath := filepath.Join(tmpDir, "AppRun")
	if _, err := os.Stat(appRunPath); os.IsNotExist(err) {
		return nil
	}

	// 1. Parse AppRun for extra search paths
	extraSearchPaths := []string{}
	file, err := os.Open(appRunPath)
	if err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.Contains(line, "LD_LIBRARY_PATH=") {
				// Very basic extraction of paths containing $HERE or ${HERE}
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					val := parts[1]
					pathParts := strings.Split(val, ":")
					for _, p := range pathParts {
						p = strings.Trim(p, "\"")
						p = strings.TrimPrefix(p, "export ")
						if strings.Contains(p, "HERE") {
							// Replace $HERE and ${HERE} with the actual temp squashfs-root
							resolved := strings.ReplaceAll(p, "$HERE", tmpDir)
							resolved = strings.ReplaceAll(resolved, "${HERE}", tmpDir)
							// Handle $(readlink -f ...) wrapping if present
							resolved = strings.TrimPrefix(resolved, "$(readlink -f ")
							resolved = strings.TrimSuffix(resolved, ")")
							resolved = strings.Trim(resolved, "\"")
							resolved = strings.Trim(resolved, "'")
							extraSearchPaths = append(extraSearchPaths, resolved)
						}
					}
				}
			}
		}
		file.Close()
	}

	// 2. Collect all direct libraries from all internal ELF binaries
	allDirectLibs := make(map[string]bool)
	for _, lib := range libs {
		allDirectLibs[lib] = true
	}

	_ = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		magic := make([]byte, 4)
		if n, _ := f.Read(magic); n < 4 || string(magic) != "\x7fELF" {
			return nil
		}

		elfF, err := elf.Open(path)
		if err != nil {
			return nil
		}
		defer elfF.Close()

		direct, _ := elfF.ImportedLibraries()
		for _, lib := range direct {
			allDirectLibs[lib] = true
		}
		return nil
	})

	uniqueDirect := make([]string, 0, len(allDirectLibs))
	for lib := range allDirectLibs {
		uniqueDirect = append(uniqueDirect, lib)
	}

	// 3. Recursively resolve everything using the AppImage's internal search paths
	// We use the first ELF in tmpDir as a dummy 'path' to ResolveTransitiveDependencies 
	// to trigger search path extraction, or just pass the AppImage path itself.
	allLibs, proxyReqMap, _ := elfparser.ResolveTransitiveDependencies(path, uniqueDirect, extraSearchPaths, "", "/")

	// Separate direct and transitive for AppImage reporting as well
	directMap := make(map[string]bool)
	for _, l := range uniqueDirect {
		directMap[l] = true
	}

	var transitiveLibs []string
	for l := range allLibs {
		if !directMap[l] {
			transitiveLibs = append(transitiveLibs, l)
		}
	}

	return auditAppRun(appRunPath, uniqueDirect, transitiveLibs, extraSearchPaths, proxyReqMap)
}

func auditAppRun(scriptPath string, directLibs []string, transitiveLibs []string, safePaths []string, proxyReqMap map[string]bool) []*hijack.HijackCandidate {
	var findings []*hijack.HijackCandidate
	file, err := os.Open(scriptPath)
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "#") {
			continue
		}

		// Look for insecure environment variable exports
		// Pattern: export VAR=...:$VAR (without safety check)
		if strings.HasPrefix(line, "export ") && strings.Contains(line, "=") {
			parts := strings.SplitN(line[7:], "=", 2)
			vVar := strings.TrimSpace(parts[0])
			
			// If the variable is used in the value with a leading colon (e.g. :$VAR or :${VAR})
			// and there is no protective check on the line (like [ -z "$VAR" ]), it's a finding.
			if strings.Contains(parts[1], ":$"+vVar) || strings.Contains(parts[1], ":${"+vVar+"}") {
				if vVar == "LD_LIBRARY_PATH" {
					// Evaluate Direct Dependencies first (Higher Signal)
					for _, lib := range directLibs {
						if !isShielded(lib, safePaths) {
							findings = append(findings, &hijack.HijackCandidate{
								Category:       "Environment Poisoning",
								RawRunPath:     fmt.Sprintf("Internal AppRun:%d", lineNum),
								ResolvedDir:    "Runtime Environment",
								Action:         fmt.Sprintf("CWD HIJACK: Script poisons %s when empty. Ensure it is unset, drop malicious library in CWD, and execute.", vVar),
								Library:        lib,
								CanHijack:      true,
								DependencyType: "Direct",
								ProxyRequired:  proxyReqMap[lib],
							})
						}
					}
					// Evaluate Transitive Dependencies (Lower Signal)
					for _, lib := range transitiveLibs {
						if !isShielded(lib, safePaths) {
							findings = append(findings, &hijack.HijackCandidate{
								Category:       "Environment Poisoning",
								RawRunPath:     fmt.Sprintf("Internal AppRun:%d", lineNum),
								ResolvedDir:    "Runtime Environment",
								Action:         fmt.Sprintf("CWD HIJACK: Script poisons %s when empty. Ensure it is unset, drop malicious library in CWD, and execute.", vVar),
								Library:        lib,
								CanHijack:      true,
								DependencyType: "Transitive",
								ProxyRequired:  proxyReqMap[lib],
							})
						}
					}
				} else {
					findings = append(findings, &hijack.HijackCandidate{
						Category:       "Environment Poisoning",
						RawRunPath:     fmt.Sprintf("Internal AppRun:%d", lineNum),
						ResolvedDir:    "Runtime Environment",
						Action:         fmt.Sprintf("CWD HIJACK: Script poisons %s when empty. Ensure it is unset, and execute the AppImage.", vVar),
						Library:        vVar,
						CanHijack:      true,
						DependencyType: "Direct", // Environment variables are direct vectors
						IsEnvVar:       true,
					})
				}
			}
		}

	}

	return findings
}

func isShielded(lib string, safePaths []string) bool {
	for _, sp := range safePaths {
		fullPath := filepath.Join(sp, lib)
		if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}
