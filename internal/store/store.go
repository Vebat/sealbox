// Package store persists sealed objects in Postgres.
//
// Delete never removes a row. It nulls the wrapped per-object key, which makes
// the ciphertext unrecoverable everywhere it was ever copied: replicas,
// backups, dumps. The ciphertext itself is kept, so an erase is visible and
// auditable rather than silently gone.
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

var indexKeyAAD = []byte("keys/" + indexKeyName)

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
	sealed, err := env.Seal(candidate, indexKeyAAD)
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
	key, err := env.Open(sealed, indexKeyAAD)
	if err != nil {
		return nil, fmt.Errorf("wrapped by master key %s: %w", sealed.KeyID, err)
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

// Put stores one item. See PutMany.
func (s *Store) Put(ctx context.Context, collection string, plaintext []byte, indexed map[string]string) (string, error) {
	ids, err := s.PutMany(ctx, collection, []Item{{Plaintext: plaintext, Indexed: indexed}})
	if err != nil {
		return "", err
	}
	return ids[0], nil
}

// PutMany seals every item under its own fresh key and stores all of them,
// with their blind-index entries, in one transaction: all land or none do.
// The returned ids, in item order, are the tokens callers keep instead of
// the data.
func (s *Store) PutMany(ctx context.Context, collection string, items []Item) ([]string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	ids := make([]string, 0, len(items))
	for _, it := range items {
		id := newID()
		sealed, err := s.env.Seal(it.Plaintext, aad(collection, id))
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
		ids = append(ids, id)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return ids, nil
}

// Get returns the plaintext of one live object.
func (s *Store) Get(ctx context.Context, collection, id string) ([]byte, error) {
	found, err := s.GetMany(ctx, collection, []string{id})
	if err != nil {
		return nil, err
	}
	plaintext, ok := found[id]
	if !ok {
		return nil, ErrNotFound
	}
	return plaintext, nil
}

// GetMany returns the plaintext of every live object among ids, keyed by id.
// Ids that do not exist, were deleted, or belong to another collection are
// absent from the result.
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
		plaintext, err := s.env.Open(sealed, aad(collection, id))
		if err != nil {
			return nil, err
		}
		found[id] = plaintext
	}
	return found, rows.Err()
}

// Search returns the ids of live objects whose indexed field equals the
// normalized value. Only the keyed hash reaches the database.
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
// deleted, and its index entries go away so a search no longer finds it.
// The ciphertext stays but can never be opened again.
func (s *Store) Delete(ctx context.Context, collection, id string) error {
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
	return tx.Commit(ctx)
}

// Rotate re-wraps the blind-index key and every live per-object key that is
// not yet under the current master key. Ciphertext is never touched, and
// rows are handled in pages with no long transaction, so it is safe to run
// while serving. Rows that cannot be re-wrapped, because they name a master
// key this server does not hold or because they no longer open at all, are
// logged by id, counted in skipped, and left as they are: one bad row must
// not block the rotation of every other.
func (s *Store) Rotate(ctx context.Context) (rotated, skipped int, err error) {
	current := s.env.CurrentKeyID()

	var sealed envelope.Sealed
	if err := s.pool.QueryRow(ctx,
		`SELECT key_id, wrapped_dek, ciphertext FROM keys WHERE name = $1`, indexKeyName).
		Scan(&sealed.KeyID, &sealed.WrappedDEK, &sealed.Ciphertext); err != nil {
		return 0, 0, err
	}
	if re, changed, err := s.env.Rewrap(sealed, indexKeyAAD); err != nil {
		return 0, 0, fmt.Errorf("blind-index key: %w", err)
	} else if changed {
		if _, err := s.pool.Exec(ctx,
			`UPDATE keys SET key_id = $1, wrapped_dek = $2 WHERE name = $3 AND key_id = $4`,
			re.KeyID, re.WrappedDEK, indexKeyName, sealed.KeyID); err != nil {
			return 0, 0, err
		}
		rotated++
	}

	type row struct {
		ID, Collection, KeyID string
		WrappedDEK            []byte
	}
	last := ""
	for {
		rows, err := s.pool.Query(ctx,
			`SELECT id, collection, key_id, wrapped_dek FROM objects
			 WHERE deleted_at IS NULL AND key_id <> $1 AND id > $2
			 ORDER BY id LIMIT 500`,
			current, last)
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
			re, _, err := s.env.Rewrap(envelope.Sealed{KeyID: r.KeyID, WrappedDEK: r.WrappedDEK}, aad(r.Collection, r.ID))
			if err != nil {
				log.Printf("store: rotate: skipping object %s: %v", r.ID, err)
				skipped++
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

// Audit appends one entry. See AuditMany.
func (s *Store) Audit(ctx context.Context, e AuditEntry) error {
	return s.AuditMany(ctx, []AuditEntry{e})
}

// AuditMany appends entries as one batch in one implicit transaction. Callers
// log a reveal before returning data, so a failed insert means no reveal.
func (s *Store) AuditMany(ctx context.Context, entries []AuditEntry) error {
	if len(entries) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, e := range entries {
		batch.Queue(
			`INSERT INTO audit_log (client, action, collection, object_id, field)
			 VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''))`,
			e.Client, e.Action, e.Collection, e.ObjectID, e.Field)
	}
	return s.pool.SendBatch(ctx, batch).Close()
}

// aad binds a ciphertext to its row so it cannot be moved to another id or
// collection at the database level.
func aad(collection, id string) []byte { return []byte(collection + "/" + id) }

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "tok_" + hex.EncodeToString(b)
}
