package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vebat/sealbox/internal/envelope"
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

// clearKeyEnv unsets every variable that feeds loadWrappers.
func clearKeyEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{
		"SEALBOX_MASTER_KEY", "SEALBOX_MASTER_KEY_FILE", "SEALBOX_MASTER_KEY_COMMAND", "SEALBOX_KMS",
		"SEALBOX_TRANSIT_ADDR", "SEALBOX_TRANSIT_KEY", "SEALBOX_TRANSIT_TOKEN", "SEALBOX_TRANSIT_TOKEN_FILE", "SEALBOX_TRANSIT_MOUNT",
		"SEALBOX_AWSKMS_KEY", "SEALBOX_AWSKMS_ENDPOINT",
	} {
		t.Setenv(v, "")
	}
}

func randomKeyB64(t *testing.T) (string, []byte) {
	t.Helper()
	k := make([]byte, 32)
	rand.Read(k)
	return base64.StdEncoding.EncodeToString(k), k
}

func TestLoadMasterKeys(t *testing.T) {
	b1, k1 := randomKeyB64(t)
	b2, k2 := randomKeyB64(t)

	// Environment: current first, previous after, comma-separated.
	clearKeyEnv(t)
	t.Setenv("SEALBOX_MASTER_KEY", b1+","+b2)
	keys, err := loadMasterKeys()
	if err != nil || len(keys) != 2 || !bytes.Equal(keys[0], k1) || !bytes.Equal(keys[1], k2) {
		t.Fatalf("env: %d keys, %v", len(keys), err)
	}

	// File: one key per line.
	clearKeyEnv(t)
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

	// No source at all is allowed: a key service may hold the current key.
	clearKeyEnv(t)
	if keys, err := loadMasterKeys(); err != nil || keys != nil {
		t.Fatalf("no source: %v, %v", keys, err)
	}

	// A blank command is no source at all, not a crash.
	t.Setenv("SEALBOX_MASTER_KEY_COMMAND", "   ")
	if keys, err := loadMasterKeys(); err != nil || keys != nil {
		t.Fatalf("blank command: %v, %v", keys, err)
	}

	for name, value := range map[string]string{
		"short":       "c2hvcnQ=",
		"not base64":  "not base64!",
		"one bad key": b1 + "," + "c2hvcnQ=",
		"only spaces": " , ",
	} {
		clearKeyEnv(t)
		t.Setenv("SEALBOX_MASTER_KEY", value)
		if _, err := loadMasterKeys(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLoadWrappers(t *testing.T) {
	ctx := context.Background()
	b1, k1 := randomKeyB64(t)

	// Local: the master key is current, nothing else.
	clearKeyEnv(t)
	t.Setenv("SEALBOX_MASTER_KEY", b1)
	ws, err := loadWrappers(ctx)
	if err != nil || len(ws) != 1 || ws[0].ID() != envelope.KeyID(k1) {
		t.Fatalf("local: %v, %v", ws, err)
	}

	// Local without any key is a configuration error, not a silent start.
	clearKeyEnv(t)
	if _, err := loadWrappers(ctx); err == nil {
		t.Fatal("local without key: expected error")
	}

	// Transit is current; the master key, if given, is a previous key for migration.
	clearKeyEnv(t)
	t.Setenv("SEALBOX_KMS", "transit")
	t.Setenv("SEALBOX_TRANSIT_ADDR", "https://vault.internal:8200")
	t.Setenv("SEALBOX_TRANSIT_KEY", "sealbox")
	tokenFile := filepath.Join(t.TempDir(), "token")
	os.WriteFile(tokenFile, []byte("s.token\n"), 0o600)
	t.Setenv("SEALBOX_TRANSIT_TOKEN_FILE", tokenFile)
	t.Setenv("SEALBOX_MASTER_KEY", b1)
	ws, err = loadWrappers(ctx)
	if err != nil || len(ws) != 2 || ws[0].ID() != "transit:transit/sealbox" || ws[1].ID() != envelope.KeyID(k1) {
		t.Fatalf("transit: %v, %v", ws, err)
	}
	t.Setenv("SEALBOX_TRANSIT_TOKEN_FILE", "")
	if _, err := loadWrappers(ctx); err == nil || !strings.Contains(err.Error(), "SEALBOX_TRANSIT_TOKEN") {
		t.Fatalf("transit without token: %v", err)
	}

	// Unknown backends are refused by name.
	clearKeyEnv(t)
	t.Setenv("SEALBOX_KMS", "hsm")
	if _, err := loadWrappers(ctx); err == nil || !strings.Contains(err.Error(), "hsm") {
		t.Fatalf("unknown kms: %v", err)
	}
}
