-- Every value lives in its own row, sealed under a per-object key that is
-- wrapped by the master key. Delete nulls wrapped_dek and keeps the row:
-- the ciphertext is then unrecoverable in every backup and replica.
CREATE TABLE objects (
	id          text        PRIMARY KEY,
	collection  text        NOT NULL,
	wrapped_dek bytea,                  -- NULL once shredded
	ciphertext  bytea       NOT NULL,
	created_at  timestamptz NOT NULL DEFAULT now(),
	deleted_at  timestamptz
);
