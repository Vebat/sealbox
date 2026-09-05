// Command sealbox runs the vault HTTP server.
//
// Configuration is taken from the environment:
//
//	SEALBOX_MASTER_KEY     required, 32 random bytes base64-encoded (openssl rand -base64 32)
//	SEALBOX_KEYS_FILE      JSON file of named clients with keys and roles, see keys.example.json
//	SEALBOX_API_KEY        one extra key holding every role, for development (openssl rand -base64 32)
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
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Vebat/sealbox/internal/api"
	"github.com/Vebat/sealbox/internal/envelope"
	"github.com/Vebat/sealbox/internal/schema"
	"github.com/Vebat/sealbox/internal/store"
)

func main() {
	masterKey, err := base64.StdEncoding.DecodeString(os.Getenv("SEALBOX_MASTER_KEY"))
	if err != nil || len(masterKey) != envelope.KeySize {
		log.Fatal("SEALBOX_MASTER_KEY must be 32 random bytes, base64-encoded: openssl rand -base64 32")
	}
	env, err := envelope.New(masterKey)
	if err != nil {
		log.Fatal(err)
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

	dbURL := os.Getenv("SEALBOX_DATABASE_URL")
	if dbURL == "" {
		log.Fatal("SEALBOX_DATABASE_URL is required")
	}
	if strings.Contains(dbURL, "sslmode=disable") {
		log.Print("warning: SEALBOX_DATABASE_URL has sslmode=disable; ciphertext and wrapped keys travel to Postgres in the clear")
	}

	addr := os.Getenv("SEALBOX_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	cert, key := os.Getenv("SEALBOX_TLS_CERT"), os.Getenv("SEALBOX_TLS_KEY")
	useTLS := cert != "" && key != ""
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
