// Package api exposes the vault over HTTP.
//
// Every route under /v1 requires "Authorization: Bearer <key>", and each key
// belongs to a client with explicit roles. Request and response bodies are
// never logged: they are the personal data this service exists to hide.
// Reads are masked unless the caller asks for reveal=full and may do so.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"regexp"

	"github.com/Vebat/sealbox/internal/schema"
	"github.com/Vebat/sealbox/internal/store"
)

// maxBody caps one object. Large blobs belong in object storage, not here.
const maxBody = 1 << 20

var collectionRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Vault is what the API needs from storage. *store.Store satisfies it.
type Vault interface {
	Put(ctx context.Context, collection string, plaintext []byte) (string, error)
	Get(ctx context.Context, collection, id string) ([]byte, error)
	Delete(ctx context.Context, collection, id string) error
}

// New returns the /v1 handler. clients must have passed ValidateClients.
func New(v Vault, s schema.Schema, clients []Client) http.Handler {
	srv := &server{vault: v, schema: s}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/collections/{collection}/objects", srv.create)
	mux.HandleFunc("GET /v1/collections/{collection}/objects/{id}", srv.get)
	mux.HandleFunc("DELETE /v1/collections/{collection}/objects/{id}", srv.delete)
	return requireKey(clients, mux)
}

type server struct {
	vault  Vault
	schema schema.Schema
}

func (s *server) create(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, RoleWrite) {
		return
	}
	collection := r.PathValue("collection")
	if !collectionRe.MatchString(collection) {
		writeError(w, http.StatusBadRequest, "invalid collection name")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "object exceeds 1 MiB")
			return
		}
		writeError(w, http.StatusBadRequest, "cannot read body")
		return
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		writeError(w, http.StatusBadRequest, "body must be a JSON object")
		return
	}
	if err := s.schema.Validate(collection, obj); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.vault.Put(r.Context(), collection, body)
	if err != nil {
		internalError(w, "put", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func (s *server) get(w http.ResponseWriter, r *http.Request) {
	reveal := r.URL.Query().Get("reveal")
	if reveal != "" && reveal != "masked" && reveal != "full" {
		writeError(w, http.StatusBadRequest, "reveal must be masked or full")
		return
	}
	role := RoleReadMasked
	if reveal == "full" {
		role = RoleReadFull
	}
	if !require(w, r, role) {
		return
	}
	collection := r.PathValue("collection")
	plaintext, err := s.vault.Get(r.Context(), collection, r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "object not found")
		return
	case err != nil:
		internalError(w, "get", err)
		return
	}
	if reveal == "full" {
		w.Header().Set("Content-Type", "application/json")
		w.Write(plaintext)
		return
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &obj); err != nil {
		internalError(w, "get: stored object is not a JSON object", err)
		return
	}
	writeJSON(w, http.StatusOK, s.schema.Mask(collection, obj))
}

func (s *server) delete(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, RoleDelete) {
		return
	}
	err := s.vault.Delete(r.Context(), r.PathValue("collection"), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "object not found")
	case err != nil:
		internalError(w, "delete", err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// internalError logs the operation and the error, never the data, and answers
// with a generic message so nothing about the failure reaches the client.
func internalError(w http.ResponseWriter, op string, err error) {
	log.Printf("api: %s: %v", op, err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
