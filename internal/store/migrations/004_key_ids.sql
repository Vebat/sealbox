-- Which master key wrapped each per-object key, so the master key can be
-- rotated by re-wrapping keys without touching ciphertext. '' marks rows
-- written before key ids existed; any loaded master key may have wrapped them.
ALTER TABLE objects ADD COLUMN key_id text NOT NULL DEFAULT '';

-- Service keys, wrapped under the master key like any per-object key.
-- blind-index is the HMAC key of the search index: rotating the master key
-- re-wraps this row, the hashes themselves never change.
CREATE TABLE keys (
	name        text  PRIMARY KEY,
	key_id      text  NOT NULL,
	wrapped_dek bytea NOT NULL,
	ciphertext  bytea NOT NULL
);
