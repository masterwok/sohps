// Package hijack provides core analysis routines for detecting
// privilege escalation vectors via shared object hijacking.
//
// This package perfectly emulates the Linux dynamic linker (ld.so)
// to evaluate ETXTBSY-evading exploit vectors across both absolute
// and dynamic search paths.
package hijack
