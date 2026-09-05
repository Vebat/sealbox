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
	"time"
	"unicode/utf8"

	"golang.org/x/time/rate"

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

var (
	collectionRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	idRe         = regexp.MustCompile(`^tok_[0-9a-f]{32}$`)
	subjectRe    = regexp.MustCompile(`^[A-Za-z0-9._:@-]{1,128}$`)
)

// subjectKey is the reserved key that names the person an object is about.
// It is taken out of the object before validation and storage.
const subjectKey = "_subject"

// Vault is what the API needs from storage. *store.Store satisfies it.
// Creates and deletes carry the acting client so their audit entries commit
// with the write; reveals and searches are logged through AuditMany first.
type Vault interface {
	PutMany(ctx context.Context, actor, collection string, items []store.Item) ([]string, error)
	GetMany(ctx context.Context, collection string, ids []string) (map[string][]byte, error)
	Delete(ctx context.Context, actor, collection, id string) error
	Search(ctx context.Context, collection, field, normalized, after string) ([]string, error)
	Subject(ctx context.Context, subject string) ([]store.Ref, error)
	DeleteSubject(ctx context.Context, actor, subject string) ([]store.Ref, error)
	AuditMany(ctx context.Context, entries []store.AuditEntry) error
}

// New returns the /v1 handler. clients must have passed ValidateClients.
func New(v Vault, s schema.Schema, clients []Client) http.Handler {
	srv := &server{vault: v, schema: s, limiters: map[string]*rate.Limiter{}}
	for _, c := range clients {
		per := cmp.Or(c.RevealPerSecond, defaultRevealPerSecond)
		srv.limiters[c.Name] = rate.NewLimiter(rate.Limit(per), int(per*5))
	}
	mux := http.NewServeMux()
	for pattern, handle := range srv.routes() {
		mux.HandleFunc(pattern, handle)
	}
	return requireKey(clients, mux)
}

type server struct {
	vault    Vault
	schema   schema.Schema
	limiters map[string]*rate.Limiter // per client, for full reveals and searches
}

// allow spends n units of the caller's reveal budget, answering 429 and
// returning false when they are not there. Masked reads are free: they hand
// out nothing an attacker wants in bulk.
func (s *server) allow(w http.ResponseWriter, r *http.Request, n int) bool {
	if l := s.limiters[clientFrom(r).Name]; l != nil && !l.AllowN(time.Now(), n) {
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return false
	}
	return true
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
		"GET /v1/subjects/{subject}":                       s.subject,
		"DELETE /v1/subjects/{subject}":                    s.eraseSubject,
	}
}

// subject lists what the vault holds about one person: collections and ids,
// no values. Role: read_masked.
func (s *server) subject(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, RoleReadMasked) {
		return
	}
	subject := r.PathValue("subject")
	if !subjectRe.MatchString(subject) {
		writeError(w, http.StatusBadRequest, "invalid subject")
		return
	}
	refs, err := s.vault.Subject(r.Context(), subject)
	if err != nil {
		internalError(w, "subject", err)
		return
	}
	if refs == nil {
		refs = []store.Ref{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"objects": refs})
}

// eraseSubject shreds every object about one person in one transaction and
// answers with what was erased. Role: delete.
func (s *server) eraseSubject(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, RoleDelete) {
		return
	}
	subject := r.PathValue("subject")
	if !subjectRe.MatchString(subject) {
		writeError(w, http.StatusBadRequest, "invalid subject")
		return
	}
	erased, err := s.vault.DeleteSubject(r.Context(), clientFrom(r).Name, subject)
	if err != nil {
		internalError(w, "erase subject", err)
		return
	}
	if erased == nil {
		erased = []store.Ref{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"erased": erased})
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
	ids, err := s.vault.PutMany(r.Context(), clientFrom(r).Name, collection, []store.Item{item})
	if err != nil {
		internalError(w, "put", err)
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
	ids, err := s.vault.PutMany(r.Context(), clientFrom(r).Name, collection, items)
	if err != nil {
		internalError(w, "put batch", err)
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
	if reveal == "full" && !s.allow(w, r, 1) {
		return
	}
	collection, id := r.PathValue("collection"), r.PathValue("id")
	if !idRe.MatchString(id) {
		writeError(w, http.StatusNotFound, "object not found")
		return
	}
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
// entry per object returned. Ids that are unknown or deleted are reported
// once under "missing"; duplicates are answered once.
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
	if req.Reveal == "full" && !s.allow(w, r, len(found)) {
		return
	}
	objects := make(map[string]any, len(found))
	missing := []string{}
	seen := map[string]bool{}
	var entries []store.AuditEntry
	for _, id := range req.IDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		plaintext, ok := found[id]
		if !ok {
			missing = append(missing, id)
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
	if !idRe.MatchString(id) {
		writeError(w, http.StatusNotFound, "object not found")
		return
	}
	err := s.vault.Delete(r.Context(), clientFrom(r).Name, collection, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "object not found")
	case err != nil:
		internalError(w, "delete", err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// search answers {"ids": [...]} for a body of exactly one indexed field and
// its value. It confirms whether a known value exists, so it has its own
// role. A full page comes with "next", the id to pass as ?after= for the
// following one.
func (s *server) search(w http.ResponseWriter, r *http.Request) {
	if !require(w, r, RoleSearch) || !s.allow(w, r, 1) {
		return
	}
	collection := r.PathValue("collection")
	after := r.URL.Query().Get("after")
	if after != "" && !idRe.MatchString(after) {
		writeError(w, http.StatusBadRequest, "after must be an object id")
		return
	}
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
		index, normalized, err := s.schema.Normalize(collection, field, value)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		ids, err := s.vault.Search(r.Context(), collection, index, normalized, after)
		if err != nil {
			internalError(w, "search", err)
			return
		}
		if ids == nil {
			ids = []string{}
		}
		if !s.audit(w, r, "search", collection, "", index) {
			return
		}
		res := map[string]any{"ids": ids}
		if len(ids) == store.SearchPage {
			res["next"] = ids[len(ids)-1]
		}
		writeJSON(w, http.StatusOK, res)
	}
}

// parseObject checks that raw is a JSON object valid for the collection and
// returns the item to store. What is stored is the object re-encoded: keys
// sorted, each key once, whitespace gone. A duplicate key therefore keeps
// only the value that was validated. The reserved "_subject" key is taken
// out and kept beside the object. Errors name a field, never a value.
func (s *server) parseObject(collection string, raw []byte) (store.Item, error) {
	if len(raw) > maxBody {
		return store.Item{}, errors.New("object exceeds 1 MiB")
	}
	if !utf8.Valid(raw) {
		return store.Item{}, errors.New("must be valid UTF-8")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return store.Item{}, errors.New("must be a JSON object")
	}
	var subject string
	if raw, ok := obj[subjectKey]; ok {
		if err := json.Unmarshal(raw, &subject); err != nil || !subjectRe.MatchString(subject) {
			return store.Item{}, fmt.Errorf("%s must be a string of up to 128 letters, digits, dots, dashes, colons or @", subjectKey)
		}
		delete(obj, subjectKey)
	}
	if err := s.schema.Validate(collection, obj); err != nil {
		return store.Item{}, err
	}
	canonical, err := json.Marshal(obj)
	if err != nil {
		return store.Item{}, errors.New("must be a JSON object")
	}
	return store.Item{Plaintext: canonical, Indexed: s.schema.Indexed(collection, obj), Subject: subject}, nil
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
