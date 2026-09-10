package hijack

// SearchPath represents a dynamic linker search directory.
// It maps the raw string extracted from the ELF binary or system config
// to the actual resolved absolute path on the host filesystem.
type SearchPath struct {
	Raw      string // The literal string from the binary (e.g., "$ORIGIN/../lib")
	Resolved string // The cleaned, absolute path on disk (e.g., "/opt/app/lib")
}

// HijackCandidate represents a verified privilege escalation path
// via shared object hijacking.
type HijackCandidate struct {
	Library        string // The name of the target shared object (e.g., "libc.so.6" or "/tmp/lib.so")
	Category       string // The vulnerability category (e.g., "Implicit CWD", "Writable Path")
	RawRunPath     string // The search path segment evaluated, or "Hardcoded Absolute Path"
	ResolvedDir    string // The absolute directory path where the vulnerability exists
	CanHijack      bool   // True if library can be hijacked
	Action         string // Instructions for exploitation
	DependencyType string // "Direct" or "Transitive"
	ProxyRequired  bool   // True if the library uses symbol versioning (harder to hijack)
	IsEnvVar       bool   // True if the 'Library' field actually holds an environment variable name
	Binary         string // The ELF binary or AppImage this candidate was found analyzing, if any (empty for system-wide checks like System Preload)
}
