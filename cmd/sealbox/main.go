// Command sealbox runs the vault HTTP server, or with the argument "rotate"
// re-wraps every key under the current master key and exits.
//
// Configuration is taken from the environment. Exactly one of these supplies
// the master keys, as base64, one per line or comma-separated; the first is
// current, the rest are previous keys still needed to open rows that have
// not been re-wrapped yet:
//
//	SEALBOX_MASTER_KEY          the keys themselves (openssl rand -base64 32)
//	SEALBOX_MASTER_KEY_FILE     a file with the keys, for Kubernetes and Docker secrets
//	SEALBOX_MASTER_KEY_COMMAND  a command that prints the keys, for a KMS; runs without a shell
//
// And:
//
//	SEALBOX_KEYS_FILE      JSON file of named clients with API keys and roles, see keys.example.json
//	SEALBOX_API_KEY        one extra API key holding every role, for development
//	SEALBOX_DATABASE_URL   required, Postgres connection string; use sslmode=verify-full
//	SEALBOX_SCHEMA         optional path to a JSON schema file, see schema.example.json
//	SEALBOX_ADDR           listen address, default :8080
//	SEALBOX_TLS_CERT       PEM certificate; together with SEALBOX_TLS_KEY enables TLS
//	SEALBOX_TLS_KEY        PEM private key
//	SEALBOX_INSECURE_HTTP  "1" allows plaintext HTTP on a non-loopback address
//
// Without a certificate the server only listens on loopback addresses, unless
// SEALBOX_INSECURE_HTTP=1 states that TLS is terminated by something in front
// of it. Whatever terminates TLS sees personal data in request bodies, so keep
// it out of anything that logs them.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Vebat/sealbox/internal/api"
	"github.com/Vebat/sealbox/internal/envelope"
	"github.com/Vebat/sealbox/internal/schema"
	"github.com/Vebat/sealbox/internal/store"
)

func main() {
	masterKeys, err := loadMasterKeys()
	if err != nil {
		log.Fatal(err)
	}
	env, err := envelope.New(masterKeys[0], masterKeys[1:]...)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("master key %s, %d previous key(s) loaded", env.CurrentKeyID(), len(masterKeys)-1)

	dbURL := os.Getenv("SEALBOX_DATABASE_URL")
	if dbURL == "" {
		log.Fatal("SEALBOX_DATABASE_URL is required")
	}
	if strings.Contains(dbURL, "sslmode=disable") {
		log.Print("warning: SEALBOX_DATABASE_URL has sslmode=disable; ciphertext and wrapped keys travel to Postgres in the clear")
	}

	if len(os.Args) > 1 && os.Args[1] == "rotate" {
		rotate(dbURL, env)
		return
	}

	clients, err := api.LoadClients(os.Getenv("SEALBOX_KEYS_FILE"))
	if err != nil {
		log.Fatal(err)
	}
	if k := os.Getenv("SEALBOX_API_KEY"); k != "" {
		clients = append(clients, api.Client{Name: "default", Key: k, Roles: api.AllRoles})
	}
	if len(clients) == 0 {
		log.Fatal("no API keys: set SEALBOX_KEYS_FILE or SEALBOX_API_KEY")
	}
	if err := api.ValidateClients(clients); err != nil {
		log.Fatal(err)
	}
	log.Printf("keys: %d client(s)", len(clients))

	sc, err := schema.Load(os.Getenv("SEALBOX_SCHEMA"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("schema: %d declared collection(s)", len(sc))

	addr := os.Getenv("SEALBOX_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	cert, key := os.Getenv("SEALBOX_TLS_CERT"), os.Getenv("SEALBOX_TLS_KEY")
	if (cert == "") != (key == "") {
		log.Fatal("set both SEALBOX_TLS_CERT and SEALBOX_TLS_KEY, or neither")
	}
	useTLS := cert != ""
	if !useTLS && !isLoopback(addr) && os.Getenv("SEALBOX_INSECURE_HTTP") != "1" {
		log.Fatalf("refusing plaintext HTTP on %s: set SEALBOX_TLS_CERT and SEALBOX_TLS_KEY, or SEALBOX_INSECURE_HTTP=1 if TLS is terminated in front of sealbox", addr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	st, err := store.Open(ctx, dbURL, env)
	cancel()
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := st.Ping(r.Context()); err != nil {
			http.Error(w, "database unreachable", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /openapi.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(api.OpenAPI)
	})
	mux.Handle("/v1/", api.New(st, sc, clients))

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	if useTLS {
		log.Printf("sealbox listening on %s (TLS)", addr)
		log.Fatal(srv.ListenAndServeTLS(cert, key))
	}
	log.Printf("sealbox listening on %s (plaintext HTTP)", addr)
	log.Fatal(srv.ListenAndServe())
}

// rotate re-wraps every key under the current master key. It runs against a
// live database while the servers keep serving, and exits non-zero if any
// row was wrapped by a key it does not have.
func rotate(dbURL string, env *envelope.Envelope) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	st, err := store.Open(ctx, dbURL, env)
	cancel()
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	rotated, skipped, err := st.Rotate(context.Background())
	if err != nil {
		log.Fatalf("rotate: %v (after %d keys)", err, rotated)
	}
	log.Printf("rotate: %d key(s) now under master key %s, %d skipped", rotated, env.CurrentKeyID(), skipped)
	if skipped > 0 {
		log.Fatalf("rotate: %d row(s) could not be re-wrapped, see the lines above: load missing master keys as previous keys and run again, or investigate rows that no longer open", skipped)
	}
}

// loadMasterKeys reads the master keys from exactly one source.
func loadMasterKeys() ([][]byte, error) {
	var raw string
	sources := 0
	if v := os.Getenv("SEALBOX_MASTER_KEY"); v != "" {
		raw = v
		sources++
	}
	if path := os.Getenv("SEALBOX_MASTER_KEY_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		raw = string(b)
		sources++
	}
	if command := os.Getenv("SEALBOX_MASTER_KEY_COMMAND"); strings.TrimSpace(command) != "" {
		args := strings.Fields(command)
		cmd := exec.Command(args[0], args[1:]...)
		// The command gets the environment it needs to reach the KMS, but
		// not sealbox's own secrets.
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, "SEALBOX_") {
				cmd.Env = append(cmd.Env, kv)
			}
		}
		out, err := cmd.Output()
		if err != nil {
			return nil, errors.New("SEALBOX_MASTER_KEY_COMMAND failed: " + err.Error())
		}
		raw = string(out)
		sources++
	}
	if sources != 1 {
		return nil, errors.New("set exactly one of SEALBOX_MASTER_KEY, SEALBOX_MASTER_KEY_FILE, SEALBOX_MASTER_KEY_COMMAND")
	}
	var keys [][]byte
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' }) {
		key, err := base64.StdEncoding.DecodeString(field)
		if err != nil || len(key) != envelope.KeySize {
			return nil, errors.New("each master key must be 32 random bytes, base64-encoded: openssl rand -base64 32")
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("no master key found")
	}
	return keys, nil
}

// isLoopback reports whether addr binds only to the local machine.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
