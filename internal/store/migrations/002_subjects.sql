-- subject_id ties an object to the person it is about, in the application's
-- own terms: a user id, a customer number. It is what an erasure request
-- names. Kept after the shred, so "everything about this person was erased
-- on this date" stays answerable.
ALTER TABLE objects ADD COLUMN subject_id text;
CREATE INDEX objects_subject ON objects (subject_id) WHERE deleted_at IS NULL;
