# sohps: Shared Object Hijack Path Scanner

`sohps` is a security auditing tool designed to identify privilege escalation vectors within Linux ELF binaries. By accurately simulating the behavior of the Linux dynamic linker (`ld.so`), `sohps` maps how binaries resolve their shared object dependencies and uncovers vulnerabilities introduced by insecure search paths, writable directories, or misconfigured environments.

---

## Vulnerability Classes

`sohps` categorizes findings into several distinct attack vectors, providing researchers with immediate context for exploitation:

| Category | Description |
| :--- | :--- |
| **Implicit CWD** | Triggered by empty entries in `RPATH` or `RUNPATH` (e.g., a trailing colon). The linker falls back to the Current Working Directory, allowing an attacker to drop a malicious library. |
| **$ORIGIN Hijack** | Vulnerabilities within directories resolved via the `$ORIGIN` macro. If the binary's directory or its relative neighbors are writable, the dependency tree can be hijacked. |
| **Writable Path** | Absolute search paths (system or user-defined) that are writable by the current user, allowing for direct replacement or tree recreation. |
| **Relative Path** | Hardcoded relative paths (e.g., `lib/`) that resolve against the CWD rather than the binary's location. |
| **Absolute Path** | Occurs when a `DT_NEEDED` entry contains a `/` (e.g., `/tmp/lib.so`). The linker bypasses all search paths and loads the file directly from the specified location. |
| **System Preload** | Checks for writable or missing `/etc/ld.so.preload` files, which can lead to system-wide hijacking of every executed process. |

---

## Capabilities

`sohps` simulates the following `ld.so` logic:

- **Linker Macro Expansion**: Full support for `$ORIGIN`, `$LIB`, and `$PLATFORM` expansion based on the target binary's architecture.
- **Search Path Prioritization**: Correctly handles the precedence of `DT_RPATH` vs. `DT_RUNPATH` and their interaction with `LD_LIBRARY_PATH`.
- **Recursive Configuration Parsing**: Parses `/etc/ld.so.conf` and all nested `include` directives to build an accurate map of system search paths.
- **HWCAP Resolution**: Simulates hardware capability searches (e.g., `tls/aarch64/aarch64`) to identify "hidden" search directories.
- **AT_SECURE Awareness**: Automatically detects SUID/SGID bits and ignores untrusted paths (relative paths, `$ORIGIN`) just as the kernel would.
- **Symlink De-duplication**: Efficiently scans large directories by resolving symlinks and analyzing each unique binary only once.

---

## Shortcomings & Limitations

While `sohps` is a powerful tool, users should be aware of its technical boundaries:

- **Static vs. Runtime**: `sohps` performs advanced static analysis of the ELF structure and filesystem permissions. It does not account for libraries loaded dynamically at runtime via `dlopen()`.
- **User-Space Perspective**: Permission checks are performed as the user running the tool. Findings may differ when run as a low-privileged user vs. root.
- **Kernel-Linker Variance**: While `sohps` mimics standard `glibc` behavior, custom or highly specialized linkers (like those in embedded systems or `musl`) may have subtle behavioral differences.
- **Environment Variables**: Outside of simulated flags like `--ld-path`, `sohps` does not automatically account for every possible environment variable that could influence `ld.so`.

---

## Installation & Building

`sohps` is written in Go and requires version 1.21 or later.

### Local Build
```bash
go build -o sohps ./cmd/sohps/main.go
```

### Cross-Platform Compilation
You can compile `sohps` for different architectures using Go's built-in cross-compilation support.

**Build for x86_64 Linux:**
```bash
GOOS=linux GOARCH=amd64 go build -o sohps_amd64 ./cmd/sohps/main.go
```

**Build for AArch64 (ARM64) Linux:**
```bash
GOOS=linux GOARCH=arm64 go build -o sohps_arm64 ./cmd/sohps/main.go
```

---

## Testing & Verification

### Running Unit Tests
The project includes a comprehensive suite of unit tests for all internal packages:
```bash
go test ./internal/... -v
```

### The `testenv` Sandbox
The `testenv/` directory contains a specialized research environment that generates intentionally vulnerable binaries. This allows researchers to verify the tool's detection logic against real-world scenarios.

1. **Build the Sandbox**:
   ```bash
   cd testenv
   make all
   ```
2. **Scan the Sandbox**:
   ```bash
   ./sohps --root /tmp/sohps_test testenv/bin
   ```
This will enumerate all 6 primary vulnerability classes, including **System Preload**, providing a clear benchmark for the tool's capabilities.

---

## Usage

```bash
# Scan a single binary
./sohps /usr/bin/clang-query

# Scan a directory recursively
./sohps /usr/local/bin

# Specify a custom system root (e.g. for firmware or rootfs analysis)
./sohps --root /mnt/rootfs /mnt/rootfs/bin

# Simulate an attacker-controlled LD_LIBRARY_PATH
./sohps --ld-path /tmp/evil /usr/bin/sudo

# Verbose scan (show safe targets) with no color for logging
./sohps -v -nc / > scan_report.txt
```

## Example

```
$ ./sohps testenv/bin
[*] Scanning testenv/bin...
[*] Found 13 ELF binaries. Starting analysis...

[*] testenv/bin/test_implicit_cwd
    [!] Implicit CWD
    Vulnerable Path : Empty Path (Implicit CWD)
    Resolved Dir    : Runtime Current Working Directory
    Action          : CWD HIJACK: Execute binary from an attacker-controlled writable directory containing a malicious payload.
    Libraries (4)   : libcustom.so, libcustom.so, libc.so.6, libc.so.6

[*] testenv/bin/test_colon_split
    [!] Writable Path
    Vulnerable Path : /tmp/sohps_test/one
    Resolved Dir    : /tmp/sohps_test/one/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/tmp/sohps_test). Recreate full path and drop payload at: /tmp/sohps_test/one/tls/aarch64/aarch64/libcustom.so
    Libraries (1)   : libcustom.so

    [!] Writable Path
    Vulnerable Path : /tmp/sohps_test/two
    Resolved Dir    : /tmp/sohps_test/two/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/tmp/sohps_test). Recreate full path and drop payload at: /tmp/sohps_test/two/tls/aarch64/aarch64/libcustom.so
    Libraries (1)   : libcustom.so

    [!] Writable Path
    Vulnerable Path : /tmp/sohps_test/one
    Resolved Dir    : /tmp/sohps_test/one/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/tmp/sohps_test). Recreate full path and drop payload at: /tmp/sohps_test/one/tls/aarch64/aarch64/libc.so.6
    Libraries (1)   : libc.so.6

    [!] Writable Path
    Vulnerable Path : /tmp/sohps_test/two
    Resolved Dir    : /tmp/sohps_test/two/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/tmp/sohps_test). Recreate full path and drop payload at: /tmp/sohps_test/two/tls/aarch64/aarch64/libc.so.6
    Libraries (1)   : libc.so.6

[*] testenv/bin/test_nodeflib
    [!] Writable Path
    Vulnerable Path : /tmp/sohps_test/nodeflib
    Resolved Dir    : /tmp/sohps_test/nodeflib/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/tmp/sohps_test). Recreate full path and drop payload at: /tmp/sohps_test/nodeflib/tls/aarch64/aarch64/libcustom.so
    Libraries (1)   : libcustom.so

    [!] Writable Path
    Vulnerable Path : /tmp/sohps_test/nodeflib
    Resolved Dir    : /tmp/sohps_test/nodeflib/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/tmp/sohps_test). Recreate full path and drop payload at: /tmp/sohps_test/nodeflib/tls/aarch64/aarch64/libc.so.6
    Libraries (1)   : libc.so.6

[*] testenv/bin/test_needed_abs
    [!] Absolute Path
    Vulnerable Path : Hardcoded Absolute Path
    Resolved Dir    : /tmp/sohps_test
    Action          : OVERWRITE: Delete existing library and replace with payload: rm /tmp/sohps_test/libcustom.so && mv payload.so /tmp/sohps_test/libcustom.so
    Libraries (1)   : /tmp/sohps_test/libcustom.so

[*] testenv/bin/test_missing_writable
    [!] Writable Path
    Vulnerable Path : /tmp/sohps_test/missing
    Resolved Dir    : /tmp/sohps_test/missing/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/tmp/sohps_test/missing). Recreate full path and drop payload at: /tmp/sohps_test/missing/tls/aarch64/aarch64/libcustom.so
    Libraries (1)   : libcustom.so

    [!] Writable Path
    Vulnerable Path : /tmp/sohps_test/missing
    Resolved Dir    : /tmp/sohps_test/missing/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/tmp/sohps_test/missing). Recreate full path and drop payload at: /tmp/sohps_test/missing/tls/aarch64/aarch64/libc.so.6
    Libraries (1)   : libc.so.6

[*] testenv/bin/test_relative
    [!] Relative Path
    Vulnerable Path : ./lib
    Resolved Dir    : /home/foo/dev/sohps/lib/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/home/foo/dev/sohps). Recreate full path and drop payload at: /home/foo/dev/sohps/lib/tls/aarch64/aarch64/libcustom.so
    Libraries (1)   : libcustom.so

    [!] Relative Path
    Vulnerable Path : ./lib
    Resolved Dir    : /home/foo/dev/sohps/lib/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/home/foo/dev/sohps). Recreate full path and drop payload at: /home/foo/dev/sohps/lib/tls/aarch64/aarch64/libc.so.6
    Libraries (1)   : libc.so.6

[*] testenv/bin/test_origin
    [!] $ORIGIN Hijack
    Vulnerable Path : $ORIGIN/../lib
    Resolved Dir    : /home/foo/dev/sohps/testenv/lib/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/home/foo/dev/sohps/testenv). Recreate full path and drop payload at: /home/foo/dev/sohps/testenv/lib/tls/aarch64/aarch64/libcustom.so
    Libraries (1)   : libcustom.so

    [!] $ORIGIN Hijack
    Vulnerable Path : $ORIGIN/../lib
    Resolved Dir    : /home/foo/dev/sohps/testenv/lib/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/home/foo/dev/sohps/testenv). Recreate full path and drop payload at: /home/foo/dev/sohps/testenv/lib/tls/aarch64/aarch64/libc.so.6
    Libraries (1)   : libc.so.6

[*] testenv/bin/test_rpath
    [!] Writable Path
    Vulnerable Path : /tmp/sohps_test/rpath
    Resolved Dir    : /tmp/sohps_test/rpath/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/tmp/sohps_test). Recreate full path and drop payload at: /tmp/sohps_test/rpath/tls/aarch64/aarch64/libcustom.so
    Libraries (1)   : libcustom.so

    [!] Writable Path
    Vulnerable Path : /tmp/sohps_test/rpath
    Resolved Dir    : /tmp/sohps_test/rpath/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/tmp/sohps_test). Recreate full path and drop payload at: /tmp/sohps_test/rpath/tls/aarch64/aarch64/libc.so.6
    Libraries (1)   : libc.so.6

[*] testenv/bin/test_trailing_colon
    [!] Writable Path
    Vulnerable Path : /tmp
    Resolved Dir    : /tmp/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/tmp). Recreate full path and drop payload at: /tmp/tls/aarch64/aarch64/libc.so.6
    Libraries (1)   : libc.so.6

    [!] Implicit CWD
    Vulnerable Path : Empty Path (Implicit CWD)
    Resolved Dir    : Runtime Current Working Directory
    Action          : CWD HIJACK: Execute binary from an attacker-controlled writable directory containing a malicious payload.
    Libraries (1)   : libc.so.6

[*] testenv/bin/test_writable_file
    [!] Writable Path
    Vulnerable Path : /tmp/sohps_writable_file
    Resolved Dir    : /tmp/sohps_writable_file
    Action          : RECREATE: Rename writable parent (/tmp) and recreate path to drop payload: mv /tmp/sohps_writable_file <backup> && mkdir -p /tmp/sohps_writable_file
    Libraries (1)   : libcustom.so

    [!] Writable Path
    Vulnerable Path : /tmp/sohps_writable_file
    Resolved Dir    : /tmp/sohps_writable_file/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/tmp). Recreate full path and drop payload at: /tmp/sohps_writable_file/tls/aarch64/aarch64/libc.so.6
    Libraries (1)   : libc.so.6

[*] testenv/bin/test_writable_path
    [!] Writable Path
    Vulnerable Path : /tmp/sohps_test
    Resolved Dir    : /tmp/sohps_test/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/tmp/sohps_test). Recreate full path and drop payload at: /tmp/sohps_test/tls/aarch64/aarch64/libc.so.6
    Libraries (1)   : libc.so.6

    [!] Writable Path
    Vulnerable Path : /tmp/sohps_test
    Resolved Dir    : /tmp/sohps_test
    Action          : OVERWRITE: Delete existing library and replace with payload: rm /tmp/sohps_test/libcustom.so && mv payload.so /tmp/sohps_test/libcustom.so
    Libraries (1)   : libcustom.so

[*] testenv/bin/test_runpath
    [!] Writable Path
    Vulnerable Path : /tmp/sohps_test/runpath
    Resolved Dir    : /tmp/sohps_test/runpath/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/tmp/sohps_test). Recreate full path and drop payload at: /tmp/sohps_test/runpath/tls/aarch64/aarch64/libcustom.so
    Libraries (1)   : libcustom.so

    [!] Writable Path
    Vulnerable Path : /tmp/sohps_test/runpath
    Resolved Dir    : /tmp/sohps_test/runpath/tls/aarch64/aarch64
    Action          : RECREATE: Writable parent (/tmp/sohps_test). Recreate full path and drop payload at: /tmp/sohps_test/runpath/tls/aarch64/aarch64/libc.so.6
    Libraries (1)   : libc.so.6

[*] Progress: [13/13] 100.0%
[*] Scan complete.
```
