// Command sealbox runs the vault HTTP server, or with the argument "rotate"
// re-wraps every key under the current wrapping key and exits.
//
// Configuration is taken from the environment.
//
// The wrapping key. SEALBOX_KMS selects where it lives:
//
//	local (default)  a master key held by this process, from exactly one of
//	                 SEALBOX_MASTER_KEY, SEALBOX_MASTER_KEY_FILE, SEALBOX_MASTER_KEY_COMMAND
//	transit          the transit engine of Vault or OpenBao: SEALBOX_TRANSIT_ADDR, SEALBOX_TRANSIT_KEY,
//	                 SEALBOX_TRANSIT_TOKEN or SEALBOX_TRANSIT_TOKEN_FILE, SEALBOX_TRANSIT_MOUNT (default transit)
//	awskms           AWS KMS, in binaries built with -tags awskms: SEALBOX_AWSKMS_KEY, the standard
//	                 AWS credential and region environment, SEALBOX_AWSKMS_ENDPOINT for emulators
//
// Master keys are base64, one per line or comma-separated. Under local the
// first is current and the rest are previous keys still needed to open rows
// that have not been re-wrapped. Under transit or awskms every master key
// given is a previous key, which is how a database migrates to a key
// service: set SEALBOX_KMS, keep the master key, run "sealbox rotate", drop it.
//
// Everything else:
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
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
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
	ctx := context.Background()
	wrappers, err := loadWrappers(ctx)
	if err != nil {
		log.Fatal(err)
	}
	env := envelope.New(wrappers[0], wrappers[1:]...)
	log.Printf("wrapping key %s, %d previous key(s) loaded", env.CurrentKeyID(), len(wrappers)-1)

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

	openCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	st, err := store.Open(openCtx, dbURL, env)
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

// rotate re-wraps every key under the current wrapping key. It runs against
// a live database while the servers keep serving, and exits non-zero if any
// row could not be re-wrapped.
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
	log.Printf("rotate: %d key(s) now under %s, %d skipped", rotated, env.CurrentKeyID(), skipped)
	if skipped > 0 {
		log.Fatalf("rotate: %d row(s) could not be re-wrapped, see the lines above: load missing keys as previous keys and run again, or investigate rows that no longer open", skipped)
	}
}

// loadWrappers returns the wrapping keys, current first. SEALBOX_KMS picks
// where the current one lives; local master keys, when given, come after it
// as previous keys.
func loadWrappers(ctx context.Context) ([]envelope.Wrapper, error) {
	keys, err := loadMasterKeys()
	if err != nil {
		return nil, err
	}
	var local []envelope.Wrapper
	for _, key := range keys {
		w, err := envelope.NewLocal(key)
		if err != nil {
			return nil, err
		}
		local = append(local, w)
	}
	switch kms := os.Getenv("SEALBOX_KMS"); kms {
	case "", "local":
		if len(local) == 0 {
			return nil, errors.New("no master key: set SEALBOX_MASTER_KEY, SEALBOX_MASTER_KEY_FILE or SEALBOX_MASTER_KEY_COMMAND")
		}
		return local, nil
	case "transit":
		addr, key := os.Getenv("SEALBOX_TRANSIT_ADDR"), os.Getenv("SEALBOX_TRANSIT_KEY")
		if addr == "" || key == "" {
			return nil, errors.New("SEALBOX_KMS=transit needs SEALBOX_TRANSIT_ADDR and SEALBOX_TRANSIT_KEY")
		}
		token, err := secret("SEALBOX_TRANSIT_TOKEN")
		if err != nil {
			return nil, err
		}
		mount := cmp.Or(os.Getenv("SEALBOX_TRANSIT_MOUNT"), "transit")
		return append([]envelope.Wrapper{envelope.NewTransit(addr, mount, key, token)}, local...), nil
	case "awskms":
		w, err := envelope.NewAWSKMS(ctx, os.Getenv("SEALBOX_AWSKMS_KEY"), os.Getenv("SEALBOX_AWSKMS_ENDPOINT"))
		if err != nil {
			return nil, err
		}
		return append([]envelope.Wrapper{w}, local...), nil
	default:
		return nil, fmt.Errorf("SEALBOX_KMS=%q: expected local, transit or awskms", kms)
	}
}

// secret reads NAME, or the file named by NAME_FILE.
func secret(name string) (string, error) {
	if v := os.Getenv(name); v != "" {
		return v, nil
	}
	if path := os.Getenv(name + "_FILE"); path != "" {
		b, err := os.ReadFile(path)
		return strings.TrimSpace(string(b)), err
	}
	return "", fmt.Errorf("%s or %s_FILE is required", name, name)
}

// loadMasterKeys reads local master keys from at most one source. No source
// at all yields no keys, which is fine when a key service holds the current
// key.
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
		// The command gets the environment it needs to reach its backend,
		// but not sealbox's own secrets.
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
	switch {
	case sources == 0:
		return nil, nil
	case sources > 1:
		return nil, errors.New("set at most one of SEALBOX_MASTER_KEY, SEALBOX_MASTER_KEY_FILE, SEALBOX_MASTER_KEY_COMMAND")
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
		return nil, errors.New("the master key source is set but holds no key")
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
