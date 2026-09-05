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

// Store seals values before they reach Postgres and opens them after.
type Store struct {
	pool *pgxpool.Pool
	env  *envelope.Envelope
}

// Open connects to databaseURL and applies pending migrations.
func Open(ctx context.Context, databaseURL string, env *envelope.Envelope) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := migrateUp(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return &Store{pool: pool, env: env}, nil
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

// Close releases the connection pool.
func (s *Store) Close() { s.pool.Close() }

// Ping reports whether the database is reachable.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Put seals plaintext under a fresh key and stores it. The returned id is the
// token the caller keeps instead of the data.
func (s *Store) Put(ctx context.Context, collection string, plaintext []byte) (string, error) {
	id := newID()
	sealed, err := s.env.Seal(plaintext, aad(collection, id))
	if err != nil {
		return "", err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO objects (id, collection, wrapped_dek, ciphertext) VALUES ($1, $2, $3, $4)`,
		id, collection, sealed.WrappedDEK, sealed.Ciphertext)
	if err != nil {
		return "", err
	}
	return id, nil
}

// Get returns the plaintext of a live object.
func (s *Store) Get(ctx context.Context, collection, id string) ([]byte, error) {
	var sealed envelope.Sealed
	err := s.pool.QueryRow(ctx,
		`SELECT wrapped_dek, ciphertext FROM objects
		 WHERE id = $1 AND collection = $2 AND deleted_at IS NULL`,
		id, collection).Scan(&sealed.WrappedDEK, &sealed.Ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.env.Open(sealed, aad(collection, id))
}

// Delete shreds the object: its wrapped key is destroyed and the row is marked
// deleted. The ciphertext stays but can never be opened again.
func (s *Store) Delete(ctx context.Context, collection, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE objects SET wrapped_dek = NULL, deleted_at = now()
		 WHERE id = $1 AND collection = $2 AND deleted_at IS NULL`,
		id, collection)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// aad binds a ciphertext to its row so it cannot be moved to another id or
// collection at the database level.
func aad(collection, id string) []byte { return []byte(collection + "/" + id) }

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "tok_" + hex.EncodeToString(b)
}
