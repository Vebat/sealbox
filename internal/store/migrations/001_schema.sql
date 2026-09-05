-- +goose Up
-- objects: every value in its own row, sealed under a per-object key that is
-- wrapped by the master key named by key_id. Delete nulls wrapped_dek and
-- keeps the row: the ciphertext is then unrecoverable here and in every
-- backup taken afterwards. Earlier backups still carry the wrapped key until
-- the master key of that time is retired.
CREATE TABLE objects (
	id          text        PRIMARY KEY,
	collection  text        NOT NULL,
	key_id      text        NOT NULL,
	wrapped_dek bytea,                  -- NULL once shredded
	ciphertext  bytea       NOT NULL,
	created_at  timestamptz NOT NULL DEFAULT now(),
	deleted_at  timestamptz
);

-- blind_index: exact-match lookup on indexed fields. hash is HMAC-SHA256 of
-- the normalized value under the blind-index key from the keys table, so a
-- dump cannot be used to test guesses. Rows go away when the object is shredded.
CREATE TABLE blind_index (
	collection text  NOT NULL,
	field      text  NOT NULL,
	hash       bytea NOT NULL,
	object_id  text  NOT NULL REFERENCES objects (id),
	PRIMARY KEY (collection, field, hash, object_id)
);
CREATE INDEX blind_index_object ON blind_index (collection, object_id);

-- keys: service keys, wrapped like any per-object key. blind-index is the
-- HMAC key of the search index: rotating the master key re-wraps this row,
-- the hashes themselves never change. Back this table up with the rest.
CREATE TABLE keys (
	name        text  PRIMARY KEY,
	key_id      text  NOT NULL,
	wrapped_dek bytea NOT NULL,
	ciphertext  bytea NOT NULL
);

-- audit_log: who did what, when. Never a value. Reveals are written before
-- the data is returned; creates and deletes in the same transaction as the
-- write. sealbox only ever inserts here.
CREATE TABLE audit_log (
	id         bigserial   PRIMARY KEY,
	at         timestamptz NOT NULL DEFAULT now(),
	client     text        NOT NULL,
	action     text        NOT NULL,
	collection text        NOT NULL,
	object_id  text,
	field      text
);
CREATE INDEX audit_log_object ON audit_log (collection, object_id, at);
