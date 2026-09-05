//go:build linux

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// harden keeps key material out of places it could leak from on this host:
// no core dumps, and no ptrace by other processes of the same user. It
// matters most with a local master key, which lives in this process.
func harden() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("mark process non-dumpable: %w", err)
	}
	return nil
}
