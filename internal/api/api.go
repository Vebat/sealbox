// Package api exposes the vault over HTTP.
//
// Every route under /v1 requires "Authorization: Bearer <key>", and each key
// belongs to a client with explicit roles. Request and response bodies are
// never logged: they are the personal data this service exists to hide.
// Reads are masked unless the caller asks for reveal=full and may do so, and
// every reveal is written to the audit log before the data is returned.
package api

import (
	"cmp"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"slices"

	"github.com/Vebat/sealbox/internal/schema"
	"github.com/Vebat/sealbox/internal/store"
)

// OpenAPI is the API description. A test checks that it documents exactly
// the routes registered here; the server serves it at /openapi.json.
//
//go:embed openapi.json
var OpenAPI []byte

const (
	maxBody      = 1 << 20   // one object; large blobs belong in object storage
	maxBatch     = 1000      // objects or ids in one batch request
	maxBatchBody = 16 << 20  // a batch of objects
	maxIDsBody   = 128 << 10 // a batch reveal request: ids only
	maxQuery     = 4096      // a search: one field, one value
)

var collectionRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Vault is what the API needs from storage. *store.Store satisfies it.
type Vault interface {
	PutMany(ctx context.Context, collection string, items []store.Item) ([]string, error)
	GetMany(ctx context.Context, collection string, ids []string) (map[string][]byte, error)
	Delete(ctx context.Context, collection, id string) error
	Search(ctx context.Context, collection, field, normalized string) ([]string, error)
	AuditMany(ctx context.Context, entries []store.AuditEntry) error
}

// New returns the /v1 handler. clients must have passed ValidateClients.
func New(v Vault, s schema.Schema, clients []Client) http.Handler {
	srv := &server{vault: v, schema: s}
	mux := http.NewServeMux()
	for pattern, handle := range srv.routes() {
		mux.HandleFunc(pattern, handle)
	}
	return requireKey(clients, mux)
}

type server struct {
	vault  Vault
	schema schema.Schema
}

// routes maps mux patterns to handlers. openapi.json must document exactly
// these; a test checks.
func (s *server) routes() map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"POST /v1/collections/{collection}/objects":        s.create,
		"POST /v1/collections/{collection}/objects/batch":  s.createBatch,
		"POST /v1/collections/{collection}/objects/reveal": s.revealBatch,
		"GET /v1/collections/{collection}/objects/{id}":    s.get,
		"DELETE /v1/collections/{collection}/objects/{id}": s.delete,
		"POST /v1/collections/{collection}/search":         s.search,
	}
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
	body, ok := readBody(w, r, maxBody)
	if !ok {
		return
	}
	item, err := s.parseObject(collection, body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ids, err := s.vault.PutMany(r.Context(), collection, []store.Item{item})
	if err != nil {
		internalError(w, "put", err)
		return
	}
	// ponytail: create and delete are logged after the write, not inside its
	// transaction; move the entry into the store transaction if auditors need
	// the two to be atomic.
	if !s.audit(w, r, "create", collection, ids[0], "") {
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": ids[0]})
}

// createBatch stores up to maxBatch objects in one transaction. One invalid
// object fails the whole batch, named by position.
func (s *server) createBatch(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, RoleWrite) {
		return
	}
	collection := r.PathValue("collection")
	if !collectionRe.MatchString(collection) {
		writeError(w, http.StatusBadRequest, "invalid collection name")
		return
	}
	body, ok := readBody(w, r, maxBatchBody)
	if !ok {
		return
	}
	var req struct {
		Objects []json.RawMessage `json:"objects"`
	}
	if err := json.Unmarshal(body, &req); err != nil || len(req.Objects) == 0 {
		writeError(w, http.StatusBadRequest, `body must be {"objects": [...]} with at least one object`)
		return
	}
	if len(req.Objects) > maxBatch {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("at most %d objects per batch", maxBatch))
		return
	}
	items := make([]store.Item, 0, len(req.Objects))
	for i, raw := range req.Objects {
		item, err := s.parseObject(collection, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("objects[%d]: %v", i, err))
			return
		}
		items = append(items, item)
	}
	ids, err := s.vault.PutMany(r.Context(), collection, items)
	if err != nil {
		internalError(w, "put batch", err)
		return
	}
	entries := make([]store.AuditEntry, len(ids))
	for i, id := range ids {
		entries[i] = store.AuditEntry{Action: "create", Collection: collection, ObjectID: id}
	}
	if !s.auditMany(w, r, entries) {
		return
	}
	writeJSON(w, http.StatusCreated, map[string][]string{"ids": ids})
}

func (s *server) get(w http.ResponseWriter, r *http.Request) {
	reveal := r.URL.Query().Get("reveal")
	if reveal != "" && reveal != "masked" && reveal != "full" {
		writeError(w, http.StatusBadRequest, "reveal must be masked or full")
		return
	}
	if !require(w, r, revealRole(reveal)) {
		return
	}
	collection, id := r.PathValue("collection"), r.PathValue("id")
	found, err := s.vault.GetMany(r.Context(), collection, []string{id})
	if err != nil {
		internalError(w, "get", err)
		return
	}
	plaintext, ok := found[id]
	if !ok {
		writeError(w, http.StatusNotFound, "object not found")
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
	masked, err := s.render(collection, plaintext, false)
	if err != nil {
		internalError(w, "get: stored object is not a JSON object", err)
		return
	}
	writeJSON(w, http.StatusOK, masked)
}

// revealBatch returns up to maxBatch objects in one call and logs one audit
// entry per object returned. Ids that are unknown, deleted, or duplicated
// are reported once under "missing" or ignored.
func (s *server) revealBatch(w http.ResponseWriter, r *http.Request) {
	collection := r.PathValue("collection")
	body, ok := readBody(w, r, maxIDsBody)
	if !ok {
		return
	}
	var req struct {
		IDs    []string `json:"ids"`
		Reveal string   `json:"reveal"`
	}
	if err := json.Unmarshal(body, &req); err != nil || len(req.IDs) == 0 {
		writeError(w, http.StatusBadRequest, `body must be {"ids": [...], "reveal": "masked"|"full"}`)
		return
	}
	if len(req.IDs) > maxBatch {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("at most %d ids per request", maxBatch))
		return
	}
	if req.Reveal != "" && req.Reveal != "masked" && req.Reveal != "full" {
		writeError(w, http.StatusBadRequest, "reveal must be masked or full")
		return
	}
	if !require(w, r, revealRole(req.Reveal)) {
		return
	}
	found, err := s.vault.GetMany(r.Context(), collection, req.IDs)
	if err != nil {
		internalError(w, "reveal batch", err)
		return
	}
	objects := make(map[string]any, len(found))
	missing := []string{}
	var entries []store.AuditEntry
	for _, id := range req.IDs {
		if _, done := objects[id]; done {
			continue
		}
		plaintext, ok := found[id]
		if !ok {
			if !slices.Contains(missing, id) {
				missing = append(missing, id)
			}
			continue
		}
		rendered, err := s.render(collection, plaintext, req.Reveal == "full")
		if err != nil {
			internalError(w, "reveal batch: stored object is not a JSON object", err)
			return
		}
		objects[id] = rendered
		entries = append(entries, store.AuditEntry{
			Action: "reveal_" + cmp.Or(req.Reveal, "masked"), Collection: collection, ObjectID: id,
		})
	}
	if !s.auditMany(w, r, entries) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"objects": objects, "missing": missing})
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

// search answers {"ids": [...]} for a body of exactly one indexed field and
// its value. It confirms whether a known value exists, so it has its own role.
func (s *server) search(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, RoleSearch) {
		return
	}
	collection := r.PathValue("collection")
	body, ok := readBody(w, r, maxQuery)
	if !ok {
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

// parseObject checks that raw is a JSON object valid for the collection and
// returns the item to store. Errors name a field, never a value.
func (s *server) parseObject(collection string, raw []byte) (store.Item, error) {
	if len(raw) > maxBody {
		return store.Item{}, errors.New("object exceeds 1 MiB")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return store.Item{}, errors.New("must be a JSON object")
	}
	if err := s.schema.Validate(collection, obj); err != nil {
		return store.Item{}, err
	}
	return store.Item{Plaintext: raw, Indexed: s.schema.Indexed(collection, obj)}, nil
}

// render returns what a reader at this reveal level may see.
func (s *server) render(collection string, plaintext []byte, full bool) (any, error) {
	if full {
		return json.RawMessage(plaintext), nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &obj); err != nil {
		return nil, err
	}
	return s.schema.Mask(collection, obj), nil
}

func revealRole(reveal string) string {
	if reveal == "full" {
		return RoleReadFull
	}
	return RoleReadMasked
}

// audit writes one entry for the calling client. See auditMany.
func (s *server) audit(w http.ResponseWriter, r *http.Request, action, collection, objectID, field string) bool {
	return s.auditMany(w, r, []store.AuditEntry{
		{Action: action, Collection: collection, ObjectID: objectID, Field: field},
	})
}

// auditMany stamps the entries with the calling client and writes them,
// answering 500 on failure. Reveals call it before writing the response, so
// no data leaves without a log line.
func (s *server) auditMany(w http.ResponseWriter, r *http.Request, entries []store.AuditEntry) bool {
	name := clientFrom(r).Name
	for i := range entries {
		entries[i].Client = name
	}
	if err := s.vault.AuditMany(r.Context(), entries); err != nil {
		internalError(w, "audit", err)
		return false
	}
	return true
}

// readBody reads at most limit bytes and answers 413 or 400 on failure.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("body exceeds %d bytes", limit))
			return nil, false
		}
		writeError(w, http.StatusBadRequest, "cannot read body")
		return nil, false
	}
	return body, true
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
