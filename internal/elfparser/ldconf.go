package elfparser

import (
	"os"
	"path/filepath"
	"strings"
)

// parseLdConf recursively parses ld.so.conf files and follows include directives.
func parseLdConf(confPath string, visited map[string]bool) []string {
	var paths []string

	if visited == nil {
		visited = make(map[string]bool)
	}

	if visited[confPath] {
		return paths
	}
	visited[confPath] = true

	data, err := os.ReadFile(confPath)
	if err != nil {
		return paths
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if globPattern, found := strings.CutPrefix(line, "include "); found {
			globPattern = strings.TrimSpace(globPattern)

			if !filepath.IsAbs(globPattern) {
				globPattern = filepath.Join(filepath.Dir(confPath), globPattern)
			}

			matches, err := filepath.Glob(globPattern)
			if err == nil {
				for _, match := range matches {
					paths = append(paths, parseLdConf(match, visited)...)
				}
			}
		} else if strings.HasPrefix(line, "/") {
			paths = append(paths, line)
		}
	}

	return paths
}
