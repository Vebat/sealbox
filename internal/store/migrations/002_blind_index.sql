-- Exact-match lookup on indexed fields. hash is HMAC-SHA256 of the normalized
-- value under a key derived from the master key, so a dump of this table
-- cannot be used to test guesses. Rows are removed when the object is shredded.
CREATE TABLE blind_index (
	collection text  NOT NULL,
	field      text  NOT NULL,
	hash       bytea NOT NULL,
	object_id  text  NOT NULL REFERENCES objects (id),
	PRIMARY KEY (collection, field, hash, object_id)
);
