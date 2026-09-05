// Command sealbox runs the vault HTTP server.
//
// Configuration is taken from the environment:
//
//	SEALBOX_MASTER_KEY  required, 32 random bytes base64-encoded (openssl rand -base64 32)
//	SEALBOX_ADDR        listen address, default :8080
package main

import (
	"encoding/base64"
	"log"
	"net/http"
	"os"

	"github.com/Vebat/sealbox/internal/envelope"
)

func main() {
	key, err := base64.StdEncoding.DecodeString(os.Getenv("SEALBOX_MASTER_KEY"))
	if err != nil || len(key) != envelope.KeySize {
		log.Fatal("SEALBOX_MASTER_KEY must be 32 random bytes, base64-encoded: openssl rand -base64 32")
	}
	if _, err := envelope.New(key); err != nil {
		log.Fatal(err)
	}

	addr := os.Getenv("SEALBOX_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})

	log.Printf("sealbox listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
