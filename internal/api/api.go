// Package api exposes the vault over HTTP.
//
// Every route under /v1 requires "Authorization: Bearer <key>", and each key
// belongs to a client with explicit roles. Request and response bodies are
// never logged: they are the personal data this service exists to hide.
// Reads are masked unless the caller asks for reveal=full and may do so.
package api

import (
	"cmp"
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
// maxQuery caps a search body: one field, one value.
const (
	maxBody  = 1 << 20
	maxQuery = 4096
)

var collectionRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Vault is what the API needs from storage. *store.Store satisfies it.
type Vault interface {
	Put(ctx context.Context, collection string, plaintext []byte, indexed map[string]string) (string, error)
	Get(ctx context.Context, collection, id string) ([]byte, error)
	Delete(ctx context.Context, collection, id string) error
	Search(ctx context.Context, collection, field, normalized string) ([]string, error)
	Audit(ctx context.Context, e store.AuditEntry) error
}

// New returns the /v1 handler. clients must have passed ValidateClients.
func New(v Vault, s schema.Schema, clients []Client) http.Handler {
	srv := &server{vault: v, schema: s}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/collections/{collection}/objects", srv.create)
	mux.HandleFunc("GET /v1/collections/{collection}/objects/{id}", srv.get)
	mux.HandleFunc("DELETE /v1/collections/{collection}/objects/{id}", srv.delete)
	mux.HandleFunc("POST /v1/collections/{collection}/search", srv.search)
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
	id, err := s.vault.Put(r.Context(), collection, body, s.schema.Indexed(collection, obj))
	if err != nil {
		internalError(w, "put", err)
		return
	}
	// ponytail: create and delete are logged after the write, not inside its
	// transaction; move the entry into the store transaction if auditors need
	// the two to be atomic.
	if !s.audit(w, r, "create", collection, id, "") {
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// audit writes an entry for the calling client and answers 500 on failure.
// Reveals call it before writing the response, so no data leaves without a
// log line.
func (s *server) audit(w http.ResponseWriter, r *http.Request, action, collection, objectID, field string) bool {
	err := s.vault.Audit(r.Context(), store.AuditEntry{
		Client:     clientFrom(r).Name,
		Action:     action,
		Collection: collection,
		ObjectID:   objectID,
		Field:      field,
	})
	if err != nil {
		internalError(w, "audit", err)
		return false
	}
	return true
}

// search answers {"ids": [...]} for a body of exactly one indexed field and
// its value. It confirms whether a known value exists, so it has its own role.
func (s *server) search(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, RoleSearch) {
		return
	}
	collection := r.PathValue("collection")
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxQuery))
	if err != nil {
		writeError(w, http.StatusBadRequest, "cannot read body")
		return
	}
	var query map[string]string
	if err := json.Unmarshal(body, &query); err != nil || len(query) != 1 {
		writeError(w, http.StatusBadRequest, "body must be a JSON object with exactly one string field")
		return
	}
	for field, value := range query {
		normalized, err := s.schema.Normalize(collection, field, value)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		ids, err := s.vault.Search(r.Context(), collection, field, normalized)
		if err != nil {
			internalError(w, "search", err)
			return
		}
		if ids == nil {
			ids = []string{}
		}
		if !s.audit(w, r, "search", collection, "", field) {
			return
		}
		writeJSON(w, http.StatusOK, map[string][]string{"ids": ids})
	}
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
	collection, id := r.PathValue("collection"), r.PathValue("id")
	plaintext, err := s.vault.Get(r.Context(), collection, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "object not found")
		return
	case err != nil:
		internalError(w, "get", err)
		return
	}
	if !s.audit(w, r, "reveal_"+cmp.Or(reveal, "masked"), collection, id, "") {
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
	collection, id := r.PathValue("collection"), r.PathValue("id")
	err := s.vault.Delete(r.Context(), collection, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "object not found")
	case err != nil:
		internalError(w, "delete", err)
	case s.audit(w, r, "delete", collection, id, ""):
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
