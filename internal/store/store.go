// Package store persists sealed objects in Postgres.
//
// Delete never removes a row. It nulls the wrapped per-object key, which makes
// the ciphertext unrecoverable in this database, its replicas, and every
// backup taken afterwards. Backups taken before still hold the wrapped key;
// retiring the master key that wrapped it kills those too. The ciphertext
// itself is kept, so an erase is visible and auditable rather than silently
// gone.
package store

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/tern/v2/migrate"

	"github.com/Vebat/sealbox/internal/envelope"
)

// Schema changes are numbered SQL files, applied once each in order.
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

// ErrNotFound is returned for objects that do not exist, were deleted, or
// belong to a different collection. The cases are not distinguished.
var ErrNotFound = errors.New("store: object not found")

// The blind-index key is a service key stored in the keys table.
const indexKeyName = "blind-index"

// aad binds a wrapped key and its ciphertext to their row. The prefix keeps
// object rows and service-key rows in separate namespaces, and the NUL
// separators keep "a"+"b\x00c" apart from "a\x00b"+"c", so nothing sealed
// for one row can ever open as another.
func aad(collection, id string) []byte { return []byte("objects\x00" + collection + "\x00" + id) }

var indexKeyAAD = []byte("keys\x00" + indexKeyName)

// Store seals values before they reach Postgres and opens them after.
type Store struct {
	pool  *pgxpool.Pool
	env   *envelope.Envelope
	index *envelope.Index
}

// Open connects to databaseURL, applies pending migrations and loads the
// blind-index key, creating it on the very first start.
func Open(ctx context.Context, databaseURL string, env *envelope.Envelope) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := migrateUp(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	index, err := loadIndexKey(ctx, pool, env)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: blind-index key: %w", err)
	}
	return &Store{pool: pool, env: env, index: index}, nil
}

// migrateUp applies migrations/*.sql that are not yet recorded in
// schema_version. tern runs each file in its own transaction and holds an
// advisory lock, so several replicas may start at the same time.
func migrateUp(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	m, err := migrate.NewMigrator(ctx, conn.Conn(), "schema_version")
	if err != nil {
		return err
	}
	files, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	if err := m.LoadMigrations(files); err != nil {
		return err
	}
	return m.Migrate(ctx)
}

// loadIndexKey returns the blind-index key. Every starting replica proposes a
// fresh random key; the first insert wins and everyone reads that one back.
func loadIndexKey(ctx context.Context, pool *pgxpool.Pool, env *envelope.Envelope) (*envelope.Index, error) {
	candidate := make([]byte, envelope.KeySize)
	rand.Read(candidate)
	sealed, err := env.Seal(ctx, candidate, indexKeyAAD)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO keys (name, key_id, wrapped_dek, ciphertext) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (name) DO NOTHING`,
		indexKeyName, sealed.KeyID, sealed.WrappedDEK, sealed.Ciphertext); err != nil {
		return nil, err
	}
	if err := pool.QueryRow(ctx,
		`SELECT key_id, wrapped_dek, ciphertext FROM keys WHERE name = $1`, indexKeyName).
		Scan(&sealed.KeyID, &sealed.WrappedDEK, &sealed.Ciphertext); err != nil {
		return nil, err
	}
	key, err := env.Open(ctx, sealed, indexKeyAAD)
	if err != nil {
		return nil, fmt.Errorf("wrapped by key %s: %w", sealed.KeyID, err)
	}
	return envelope.NewIndex(key)
}

// Close releases the connection pool.
func (s *Store) Close() { s.pool.Close() }

// Ping reports whether the database is reachable.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Item is one object to store.
type Item struct {
	Plaintext []byte
	Indexed   map[string]string // field name to normalized value, for the blind index
}

// PutMany seals every item under its own fresh key and stores all of them,
// with their blind-index entries and one audit entry each, in one
// transaction: all land or none do. The returned ids, in item order, are the
// tokens callers keep instead of the data. actor names the client for the
// audit log.
func (s *Store) PutMany(ctx context.Context, actor, collection string, items []Item) ([]string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	ids := make([]string, 0, len(items))
	for _, it := range items {
		id := newID()
		sealed, err := s.env.Seal(ctx, it.Plaintext, aad(collection, id))
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO objects (id, collection, key_id, wrapped_dek, ciphertext) VALUES ($1, $2, $3, $4, $5)`,
			id, collection, sealed.KeyID, sealed.WrappedDEK, sealed.Ciphertext); err != nil {
			return nil, err
		}
		for field, value := range it.Indexed {
			if _, err := tx.Exec(ctx,
				`INSERT INTO blind_index (collection, field, hash, object_id) VALUES ($1, $2, $3, $4)`,
				collection, field, s.index.Hash(collection, field, value), id); err != nil {
				return nil, err
			}
		}
		if err := audit(ctx, tx, AuditEntry{Client: actor, Action: "create", Collection: collection, ObjectID: id}); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return ids, nil
}

// GetMany returns the plaintext of every live object among ids, keyed by id.
// Ids that do not exist, were deleted, or belong to another collection are
// absent from the result. A row that no longer opens is an error: it means
// tampering, not absence.
func (s *Store) GetMany(ctx context.Context, collection string, ids []string) (map[string][]byte, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, key_id, wrapped_dek, ciphertext FROM objects
		 WHERE collection = $1 AND id = ANY($2) AND deleted_at IS NULL`,
		collection, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := make(map[string][]byte, len(ids))
	for rows.Next() {
		var id string
		var sealed envelope.Sealed
		if err := rows.Scan(&id, &sealed.KeyID, &sealed.WrappedDEK, &sealed.Ciphertext); err != nil {
			return nil, err
		}
		plaintext, err := s.env.Open(ctx, sealed, aad(collection, id))
		if err != nil {
			return nil, fmt.Errorf("object %s: %w", id, err)
		}
		found[id] = plaintext
	}
	return found, rows.Err()
}

// Search returns the ids of live objects whose indexed field equals the
// normalized value, at most 100. Only the keyed hash reaches the database.
func (s *Store) Search(ctx context.Context, collection, field, normalized string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT object_id FROM blind_index
		 WHERE collection = $1 AND field = $2 AND hash = $3
		 ORDER BY object_id LIMIT 100`,
		collection, field, s.index.Hash(collection, field, normalized))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// Delete shreds the object: its wrapped key is destroyed, the row is marked
// deleted, its index entries go away so a search no longer finds it, and the
// audit entry lands in the same transaction. The ciphertext stays but can
// never be opened again.
func (s *Store) Delete(ctx context.Context, actor, collection, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx,
		`UPDATE objects SET wrapped_dek = NULL, deleted_at = now()
		 WHERE id = $1 AND collection = $2 AND deleted_at IS NULL`,
		id, collection)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM blind_index WHERE collection = $1 AND object_id = $2`, collection, id); err != nil {
		return err
	}
	if err := audit(ctx, tx, AuditEntry{Client: actor, Action: "delete", Collection: collection, ObjectID: id}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Rotate re-wraps the blind-index key and every live per-object key that is
// not yet under the current wrapping key, which is also how a database
// moves from a local master key to a key service. When the current wrapper
// is a key service with versions of its own, rows already under it are
// visited too and re-wrapped through the service, so rotating the key there
// completes here. Ciphertext is never touched, and rows are handled in
// pages with no long transaction, so it is safe to run while serving. Rows
// that cannot be re-wrapped, because they name a key this server does not
// hold or because they no longer open at all, are logged by id, counted in
// skipped, and left as they are: one bad row must not block the rotation of
// every other. A key service that cannot be reached stops the run instead.
//
// ponytail: one re-wrap call per row against a key service; use the
// engine's batch_input when rotating millions of rows.
func (s *Store) Rotate(ctx context.Context) (rotated, skipped int, err error) {
	current := s.env.CurrentKeyID()
	inPlace := s.env.RewrapsInPlace()

	var sealed envelope.Sealed
	if err := s.pool.QueryRow(ctx,
		`SELECT key_id, wrapped_dek, ciphertext FROM keys WHERE name = $1`, indexKeyName).
		Scan(&sealed.KeyID, &sealed.WrappedDEK, &sealed.Ciphertext); err != nil {
		return 0, 0, err
	}
	if re, changed, err := s.env.Rewrap(ctx, sealed, indexKeyAAD); err != nil {
		return 0, 0, fmt.Errorf("blind-index key: %w", err)
	} else if changed {
		tag, err := s.pool.Exec(ctx,
			`UPDATE keys SET key_id = $1, wrapped_dek = $2 WHERE name = $3 AND key_id = $4`,
			re.KeyID, re.WrappedDEK, indexKeyName, sealed.KeyID)
		if err != nil {
			return 0, 0, err
		}
		rotated += int(tag.RowsAffected())
	}

	type row struct {
		ID, Collection, KeyID string
		WrappedDEK            []byte
	}
	last := ""
	for {
		rows, err := s.pool.Query(ctx,
			`SELECT id, collection, key_id, wrapped_dek FROM objects
			 WHERE deleted_at IS NULL AND (key_id <> $1 OR $3) AND id > $2
			 ORDER BY id LIMIT 500`,
			current, last, inPlace)
		if err != nil {
			return rotated, skipped, err
		}
		page, err := pgx.CollectRows(rows, pgx.RowToStructByPos[row])
		if err != nil {
			return rotated, skipped, err
		}
		if len(page) == 0 {
			return rotated, skipped, nil
		}
		for _, r := range page {
			last = r.ID
			re, changed, err := s.env.Rewrap(ctx, envelope.Sealed{KeyID: r.KeyID, WrappedDEK: r.WrappedDEK}, aad(r.Collection, r.ID))
			if errors.Is(err, envelope.ErrOpen) || errors.Is(err, envelope.ErrUnknownKey) {
				log.Printf("store: rotate: skipping object %s: %v", r.ID, err)
				skipped++
				continue
			}
			if err != nil {
				// A key service that cannot be reached is not a bad row.
				return rotated, skipped, fmt.Errorf("object %s: %w", r.ID, err)
			}
			if !changed {
				continue
			}
			// deleted_at IS NULL again: never write a key back into a row
			// that was shredded since it was read.
			tag, err := s.pool.Exec(ctx,
				`UPDATE objects SET key_id = $1, wrapped_dek = $2
				 WHERE id = $3 AND key_id = $4 AND deleted_at IS NULL`,
				re.KeyID, re.WrappedDEK, r.ID, r.KeyID)
			if err != nil {
				return rotated, skipped, err
			}
			rotated += int(tag.RowsAffected())
		}
	}
}

// AuditEntry is one line of the audit log. Values never appear in it: only
// who did what to which object, and for searches which field was queried.
type AuditEntry struct {
	Client     string
	Action     string // create, reveal_masked, reveal_full, search, delete
	Collection string
	ObjectID   string // empty for search
	Field      string // search only
}

// AuditMany appends entries as one batch in one implicit transaction. Callers
// log a reveal before returning data, so a failed insert means no reveal.
func (s *Store) AuditMany(ctx context.Context, entries []AuditEntry) error {
	if len(entries) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, e := range entries {
		batch.Queue(auditSQL, e.Client, e.Action, e.Collection, e.ObjectID, e.Field)
	}
	return s.pool.SendBatch(ctx, batch).Close()
}

const auditSQL = `INSERT INTO audit_log (client, action, collection, object_id, field)
	VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''))`

// audit writes one entry inside a transaction, so a create or delete and
// its log line commit together or not at all.
func audit(ctx context.Context, tx pgx.Tx, e AuditEntry) error {
	_, err := tx.Exec(ctx, auditSQL, e.Client, e.Action, e.Collection, e.ObjectID, e.Field)
	return err
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "tok_" + hex.EncodeToString(b)
}
