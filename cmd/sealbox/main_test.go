package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8080": true,
		"localhost:8080": true,
		"[::1]:8080":     true,
		":8080":          false,
		"0.0.0.0:8080":   false,
		"10.0.0.5:8080":  false,
		"garbage":        false,
	} {
		if got := isLoopback(addr); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestLoadMasterKeys(t *testing.T) {
	k1, k2 := make([]byte, 32), make([]byte, 32)
	rand.Read(k1)
	rand.Read(k2)
	b1, b2 := base64.StdEncoding.EncodeToString(k1), base64.StdEncoding.EncodeToString(k2)
	clear := func() {
		for _, v := range []string{"SEALBOX_MASTER_KEY", "SEALBOX_MASTER_KEY_FILE", "SEALBOX_MASTER_KEY_COMMAND"} {
			t.Setenv(v, "")
		}
	}

	// Environment: current first, previous after, comma-separated.
	clear()
	t.Setenv("SEALBOX_MASTER_KEY", b1+","+b2)
	keys, err := loadMasterKeys()
	if err != nil || len(keys) != 2 || !bytes.Equal(keys[0], k1) || !bytes.Equal(keys[1], k2) {
		t.Fatalf("env: %d keys, %v", len(keys), err)
	}

	// File: one key per line.
	clear()
	path := filepath.Join(t.TempDir(), "master")
	os.WriteFile(path, []byte(b1+"\n"+b2+"\n"), 0o600)
	t.Setenv("SEALBOX_MASTER_KEY_FILE", path)
	if keys, err := loadMasterKeys(); err != nil || len(keys) != 2 || !bytes.Equal(keys[0], k1) {
		t.Fatalf("file: %d keys, %v", len(keys), err)
	}

	// Two sources at once is a configuration mistake.
	t.Setenv("SEALBOX_MASTER_KEY", b1)
	if _, err := loadMasterKeys(); err == nil {
		t.Fatal("two sources: expected error")
	}

	// A blank command is no source at all, not a crash.
	clear()
	t.Setenv("SEALBOX_MASTER_KEY_COMMAND", "   ")
	if _, err := loadMasterKeys(); err == nil {
		t.Fatal("blank command: expected error")
	}

	for name, value := range map[string]string{
		"short":        "c2hvcnQ=",
		"not base64":   "not base64!",
		"one bad key":  b1 + "," + "c2hvcnQ=",
		"empty string": "",
	} {
		clear()
		t.Setenv("SEALBOX_MASTER_KEY", value)
		if _, err := loadMasterKeys(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
