//go:build !linux

package main

// harden has nothing to do outside Linux, where sealbox is not expected to
// hold real data.
func harden() error { return nil }
