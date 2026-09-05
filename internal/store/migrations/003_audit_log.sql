-- Who did what, when. Never a value: only client, action, collection, object
-- id, and for searches the field name. Reveals are written before the data is
-- returned. sealbox only ever inserts here; see README for keeping the table
-- append-only at the database level.
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
