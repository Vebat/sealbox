# sealbox

Encrypted vault for personal data. Delete the key, shred the data.

> **Status: pre-alpha, not audited.** Nothing here has been reviewed by anyone but the author. Do not put real data in it yet.

## The problem

GDPR gives people the right to have their data erased. Your backups are kept for years.
PCI DSS and similar regimes audit every system that can see a card number, a passport or a diagnosis.
Every table that holds personal data widens the blast radius of the next leak.

sealbox takes personal data out of your database. Your application stores a token; sealbox stores the
ciphertext, encrypted under a key that exists only for that one object. Deleting the object destroys that key:
from then on the ciphertext is unreadable in the live database, in every replica, and in every backup taken afterwards.
This is crypto-shredding. Backups taken before the deletion still hold the object's wrapped key next to its ciphertext,
so the last step is retiring the master key on a schedule: once the master key that was current when a backup was
taken is destroyed, every object erased before that rotation is gone from that backup too. Rotation is built in.

## API

Every request carries `Authorization: Bearer <key>`. An object is a JSON object up to 1 MiB, valid UTF-8.
It is stored re-encoded: keys sorted, each key once, last value wins, no whitespace. That is what a full read returns.
Reads are masked unless the caller asks for `reveal=full` and holds the role for it.

Keys belong to named clients with explicit roles, declared in `SEALBOX_KEYS_FILE` (see [keys.example.json](keys.example.json)).
`SEALBOX_API_KEY` adds one client named `default` with every role. It exists for development; never set it in production.

| Role | Allows |
|---|---|
| `write` | `POST` objects |
| `read_masked` | `GET` with masks applied |
| `read_full` | `GET ?reveal=full`, the plaintext |
| `delete` | `DELETE` an object, or everything about a subject |
| `search` | `POST .../search`, ids by an indexed value |

`read_masked` also lists what is held about a subject, ids only.

Each client has a reveal budget, `reveal_per_second` in the keys file, default 200 with a burst of five seconds'
worth. Full reveals spend one unit per object, batch or not, and searches spend one each; over budget the
answer is 429 and nothing is revealed. Masked reads are free. Give a support desk 20 and a payment worker what
it measurably needs: the budget is what turns a stolen key into a slow leak instead of a dump.

A checkout service gets `write`. A support UI gets `read_masked`. Only the privacy tooling gets `read_full` and `delete`.
Role is checked before the object is looked up, so an unprivileged key learns nothing about what exists.

```http
POST /v1/collections/customers/objects
{ "email": "ivan@example.com", "passport": "4510 123456" }
-> 201 { "id": "tok_9f3a..." }

GET /v1/collections/customers/objects/tok_9f3a...
-> 200 { "email": "i***@example.com", "passport": "***" }

GET /v1/collections/customers/objects/tok_9f3a...?reveal=full
-> 200 { "email": "ivan@example.com", "passport": "4510 123456" }

DELETE /v1/collections/customers/objects/tok_9f3a...
-> 204, the object's key is destroyed; its ciphertext is now noise

POST /v1/collections/customers/search
{ "email": "Ivan@Example.com" }
-> 200 { "ids": ["tok_9f3a..."] }
```

Search takes exactly one indexed field and finds objects whose value is equal after normalization, 100 per page;
a full page carries `next`, the id to pass as `?after=` for the following one.
It is exact match only: you can find a record by a value you already know in full, you cannot browse.
Ranges, prefixes and free text belong in your own database, on fields that are not personal data.

An object can say who it is about with the reserved `_subject` key, a user id or customer number in your own
terms. It is kept beside the object, not in it, and it is what an erasure request names:

```http
POST /v1/collections/customers/objects
{ "_subject": "user:42", "email": "ivan@example.com" }

GET /v1/subjects/user:42
-> 200 { "objects": [ { "collection": "addresses", "id": "tok_..." }, { "collection": "customers", "id": "tok_..." } ] }

DELETE /v1/subjects/user:42
-> 200 { "erased": [ ... ] }
```

Erasing a subject crypto-shreds every object about that person across collections, in one transaction, with
one audit entry each. The subject stays on the shredded rows, so "everything about this person was erased on this
date" remains answerable. Use `_subject` on every object you store and a data subject request becomes one call.

Lists and migrations go through batches, not one request per row:

```http
POST /v1/collections/customers/objects/batch
{ "objects": [ { "email": "a@example.com" }, { "email": "b@example.com" } ] }
-> 201 { "ids": ["tok_1...", "tok_2..."] }

POST /v1/collections/customers/objects/reveal
{ "ids": ["tok_1...", "tok_2...", "tok_gone"], "reveal": "masked" }
-> 200 { "objects": { "tok_1...": { "email": "a***@example.com" }, "tok_2...": { ... } }, "missing": ["tok_gone"] }
```

A batch stores up to 1000 objects in one transaction: one invalid object fails the whole batch, named by position.
Batch reveal returns up to 1000 objects in one call and writes one audit entry per object returned.
Moving an existing table into sealbox is a loop of batches, replacing each row's columns with the returned id.

## Clients

The API is described in [openapi.json](internal/api/openapi.json), which a running server also serves at `/openapi.json`.
A test keeps it in step with the registered routes. Generate a client for your language from it, for example:

```sh
npx openapi-typescript http://localhost:8080/openapi.json -o sealbox.d.ts
```

Go programs can use the client package directly:

```go
import "github.com/Vebat/sealbox/client"

c := client.New("https://sealbox.internal:8080", os.Getenv("SEALBOX_KEY"))
id, err := c.Create(ctx, "customers", map[string]string{"email": "ivan@example.com"})

var masked map[string]string
err = c.Get(ctx, "customers", id, false, &masked)          // {"email": "i***@example.com"}
ids, err := c.Search(ctx, "customers", "email", "ivan@example.com")
objects, missing, err := c.Reveal(ctx, "customers", ids, true)
err = c.Delete(ctx, "customers", id)                       // client.ErrNotFound the second time
```

Refusals come back as `*client.Error` with the HTTP status and the server's message.

## Schemas

A schema file, passed as `SEALBOX_SCHEMA`, declares what each collection holds. See [schema.example.json](schema.example.json):

```json
{ "customers": { "fields": {
    "email":    { "type": "email", "index": true },
    "phone":    { "type": "phone", "index": true },
    "card":     { "type": "card" },
    "passport": { "type": "string" }
} } }
```

| Type | Accepts | Masked as | Normalized for search as |
|---|---|---|---|
| `string` | anything | `***` | cannot be indexed |
| `email` | `local@domain` | `i***@example.com` | trimmed, lower case |
| `phone` | 7 to 15 digits, with `+ - ( ) .` and spaces | `***4567` | digits only |
| `card` | 13 to 19 digits passing Luhn, with `-` and spaces | `**** **** **** 1234` | digits only |

Rules:

- In a declared collection every value must be a string of the declared type; unknown fields are rejected. Fields are optional.
- A collection missing from the schema is free-form: any JSON object is accepted, and a masked read hides every value as `***`.
  Field names stay visible, so do not put personal data in the keys.
- Masks are fixed per type. What they keep, the email domain and the last four digits, is visible to every holder of a `read_masked` key by design.
- `index: true` makes a field searchable. sealbox stores an HMAC-SHA256 of the normalized value, never the value, under a random
  index key that is created on first start and kept in the `keys` table wrapped by the master key. Back that table up with the rest.
  A database dump shows which records share a value, not what it is, and cannot be used to test guesses without the master key.
- Validation errors name the field, never the submitted value.
- The schema is read at startup. Change the file, restart the process. Adding `index` to a field indexes new objects
  from then on; run `sealbox reindex [collection]` with the same schema to rebuild the index for existing ones.
  It opens every object to do so, and writes a `reindex` audit entry per object to say that it did.

## Master key

Exactly one of these supplies it:

| Variable | Reads the key from |
|---|---|
| `SEALBOX_MASTER_KEY` | the variable itself |
| `SEALBOX_MASTER_KEY_FILE` | a file, for Kubernetes and Docker secrets |
| `SEALBOX_MASTER_KEY_COMMAND` | the output of a command, for a KMS or a secret store |

The value is one or more base64 keys, one per line or comma-separated. The first is the current key and wraps
every new object. The rest are previous keys, still needed to open rows that have not been re-wrapped yet.

With a KMS the key never sits in the environment; the command fetches it at startup:

```sh
SEALBOX_MASTER_KEY_COMMAND="aws kms decrypt --ciphertext-blob fileb:///etc/sealbox/master.enc --query Plaintext --output text"
SEALBOX_MASTER_KEY_COMMAND="vault kv get -field=master secret/sealbox"
```

The command runs without a shell and without sealbox's own environment variables. Wrap pipes in a script.
The shipped image is distroless, so it has no `aws`, `vault` or shell: build your own image on top of it,
or have an init container fetch the key into a file and use `SEALBOX_MASTER_KEY_FILE`.

Losing the master key loses every object. Back it up outside the database and test the restore.
sealbox logs the fingerprint of the current key at startup.

### Keeping the master key out of the process

With a local master key, whoever controls the sealbox process holds every key. `SEALBOX_KMS` moves the
wrapping key into a key service: sealbox sends each per-object key there to be wrapped and asks for it back
to be unwrapped, one call per object, and never sees the master key. A compromised process can then only
unwrap keys while it is compromised, one at a time, each call logged by the key service and revocable there.

| `SEALBOX_KMS` | Backend | Configuration |
|---|---|---|
| `local` (default) | this process | `SEALBOX_MASTER_KEY`, `_FILE` or `_COMMAND` |
| `transit` | HashiCorp Vault or OpenBao transit engine | `SEALBOX_TRANSIT_ADDR`, `SEALBOX_TRANSIT_KEY`, `SEALBOX_TRANSIT_TOKEN` or `SEALBOX_TRANSIT_TOKEN_FILE`, `SEALBOX_TRANSIT_MOUNT` (default `transit`) |
| `awskms` | AWS KMS | `SEALBOX_AWSKMS_KEY` (id, ARN or alias) and the standard AWS credential and region environment |

Create the transit key with `derived=true` and the engine also binds every wrapped key to its row. AWS KMS does the
same through the encryption context. AWS support is compiled in only with `go build -tags awskms`, or
`docker build --build-arg TAGS=awskms`, because it brings the AWS SDK; the default binary carries neither.

Moving an existing database to a key service is a rotation: set `SEALBOX_KMS`, keep the master key configured so
it opens the old rows, restart, run `sealbox rotate`, then drop the master key. Every wrap and unwrap is a network
call, so expect a few milliseconds per single read. Batch reveals go through the engine's `batch_input`, 500 keys
per round trip, so a page of a thousand objects is two calls, not a thousand.

Rotating the key inside the service is finished the same way. After `vault write -f transit/keys/sealbox/rotate`,
or a new master key version in keeper, run `sealbox rotate`: it asks the engine to re-wrap every key under the
current version, one call per object, and only rows whose version actually moved are written. Then the old
version can be retired, `min_decryption_version` in Vault, the old line in keeper's key file.

### Rotation

Rotation re-wraps keys, it does not re-encrypt data, so it runs while the service is up.

1. Generate a new key. Put it first and keep the old one after it, then restart every replica.
   New objects are wrapped under the new key; old ones still open.
2. Run `sealbox rotate` with the same configuration. It re-wraps the blind-index key and every live
   object's key in pages, prints the counts, and exits non-zero if any row was wrapped by a key it does not have.
3. Remove the old key and restart. Check that one fingerprint remains, the one logged at startup:

```sql
SELECT key_id, count(*) FROM objects WHERE deleted_at IS NULL GROUP BY 1;
```

Rotation limits future exposure. Whoever held the old key together with a dump taken while it was in use
can still open those rows.

### Erasure and backups

Rotation is also how an erasure reaches old backups. A backup holds each object's wrapped key next to its
ciphertext, so a backup taken before a deletion, plus the master key that was current then, still opens the
deleted object. Rotate on a schedule that matches your erasure promises, destroy the retired key everywhere it
was kept, and every backup older than that rotation is dead for every object erased before it. Until the
rotation happens, treat older backups as still containing the erased data.

## Audit log

Every successful action is written to the `audit_log` table: which client did what, to which object, when.
For a search, the field that was queried. Never a value, never a hash.
A create or delete commits together with its audit entry, in one transaction. A reveal or search is logged before the
data is returned: if the log cannot be written, the request fails and nothing is revealed.

| Action | Written when |
|---|---|
| `create` | an object was stored |
| `reveal_masked` | a masked read |
| `reveal_full` | a plaintext read |
| `search` | a lookup by an indexed field |
| `delete` | a crypto-shred |
| `reindex` | `sealbox reindex` opened the object to rebuild its index rows |

Read it with SQL. Everything about one person:

```sql
SELECT at, client, action FROM audit_log WHERE object_id = 'tok_...' ORDER BY at;
```

sealbox only inserts into this table, and with two database roles that is all it can do:

```sql
CREATE ROLE sealbox_owner LOGIN PASSWORD '...';   -- owns the tables, runs migrations
CREATE ROLE sealbox_app   LOGIN PASSWORD '...';   -- what the servers run as
CREATE DATABASE sealbox OWNER sealbox_owner;
```

```sh
SEALBOX_DATABASE_URL=postgres://sealbox_owner:...@db/sealbox SEALBOX_RUNTIME_ROLE=sealbox_app sealbox migrate
```

`sealbox migrate` applies pending migrations and grants `sealbox_app` exactly what a running server needs: read and
write objects and keys, add and remove index rows, and append to the audit log, which it cannot update, delete or
truncate. Run the servers as `sealbox_app` with `SEALBOX_MIGRATE=off`; they check that the schema is current and
refuse to start otherwise. Repeat `sealbox migrate` on every upgrade. Whoever holds the owner credentials can still
rewrite the log, so ship it off the box as well if you need tamper evidence against your own administrators:
`SEALBOX_AUDIT_STDOUT=1` writes every committed entry to stdout as one JSON line, for whatever collects container
output. Never a value, only client, action, collection, object id and, for searches, the field.

## Transport

sealbox terminates TLS itself: set `SEALBOX_TLS_CERT` and `SEALBOX_TLS_KEY`. Without them it refuses to listen on
anything but a loopback address, unless `SEALBOX_INSECURE_HTTP=1` says TLS is terminated in front of it. Think
before doing that: whatever terminates TLS sees personal data in request bodies, and most ingresses log bodies on error.

Connect to Postgres with `sslmode=verify-full`. sealbox warns at startup when it sees `sslmode=disable`.

With `SEALBOX_TLS_CLIENT_CA` set to a PEM bundle, only clients presenting a certificate signed by it get a TLS
session at all; API keys still say who they are. TLS is 1.3 only.

Two endpoints need no key: `GET /healthz`, which pings the database, and `GET /openapi.json`.

`SEALBOX_METRICS_ADDR=127.0.0.1:9090` serves Prometheus metrics at `/metrics` on that address, never on the API
port: requests per route and status, and time spent per route. Routes are patterns, so no id or token appears.

On Linux sealbox disables core dumps and marks itself non-dumpable at start, so a crash or a debugger of the same
user does not write key material to disk.

The container image is distroless and runs as uid 65532. Mounted files, the schema, a keys file, TLS certificate and key,
must be readable by that user.

## What it protects against

- A dump of the database, or a stolen backup: ciphertext only, per-object keys wrapped under a master key that is never stored next to the data.
- An insider with database access: same.
- Personal data leaking through application logs, analytics or search indexes: the application only ever holds tokens.
- Erasure requests against long-lived backups: crypto-shredding, completed by master key rotation.

It does **not** protect against a compromised sealbox process, a stolen master key, or an application
that decrypts a value and leaks it itself. Read [THREAT_MODEL.md](THREAT_MODEL.md) before relying on it.

## Compared to

| | sealbox | HashiCorp Vault / OpenBao | Skyflow, Evervault, Basis Theory | Google Tink |
|---|---|---|---|---|
| Open source | Apache-2.0 | BUSL / MPL | no | yes |
| Self-hosted | one binary + Postgres | yes | no | library only |
| Stores the data (tokenization) | yes | Enterprise only | yes | no |
| Per-object key, crypto-shred | yes | no | vendor-specific | you build it |
| Masking, roles, audit log | yes | partial | yes | no |

## Quickstart

```sh
printf 'SEALBOX_MASTER_KEY=%s\nSEALBOX_API_KEY=%s\n' "$(openssl rand -base64 32)" "$(openssl rand -base64 32)" > .env
docker compose up --build
```

A database belongs to one master key: the index key created on first start is wrapped under it. If you generate a new
`.env`, start over with `docker compose down -v`.

Then, in another shell:

```sh
export KEY=$(sed -n 's/^SEALBOX_API_KEY=//p' .env)
curl -s -H "Authorization: Bearer $KEY" -d '{"email":"ivan@example.com"}' localhost:8080/v1/collections/customers/objects
# {"id":"tok_..."}
curl -s -H "Authorization: Bearer $KEY" localhost:8080/v1/collections/customers/objects/tok_...
# {"email":"i***@example.com"}
curl -s -H "Authorization: Bearer $KEY" "localhost:8080/v1/collections/customers/objects/tok_...?reveal=full"
# {"email":"ivan@example.com"}
curl -s -X DELETE -H "Authorization: Bearer $KEY" localhost:8080/v1/collections/customers/objects/tok_...
```

The compose file mounts `schema.example.json`, which is why `email` is masked as an address rather than as `***`.

Or without Docker, against your own Postgres:

```sh
SEALBOX_MASTER_KEY=$(openssl rand -base64 32) SEALBOX_API_KEY=$(openssl rand -base64 32) \
SEALBOX_DATABASE_URL=postgres://user:pass@localhost:5432/sealbox SEALBOX_ADDR=127.0.0.1:8080 go run ./cmd/sealbox
```

## Releases

Every `v*` tag builds binaries for linux, windows and macOS, an SPDX SBOM, and signs each file with cosign
under this repository's GitHub identity, keyless. Verify a download before running it:

```sh
cosign verify-blob --bundle sealbox_v0.2.0_linux_amd64.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Vebat/sealbox/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  sealbox_v0.2.0_linux_amd64
```

The release notes are the tag's annotation.

## Open

Not built yet, in the order they are likely to matter:

- A third-party audit
- Partial indexes on declared fragments, such as the last four digits of a card
- A Helm chart
- Client wrappers for ORMs, and a proxy mode that keeps card numbers out of the application entirely

## Done

- [x] Envelope encryption: XChaCha20-Poly1305, fresh key per object, ciphertext bound to the object id
- [x] Postgres store; delete destroys the wrapped key, with a test that proves the ciphertext is dead
- [x] HTTP API: create, get, delete; one API key; TLS built in, plaintext only on loopback
- [x] Collection schemas from a JSON file; email, phone, card and string types; masked reads by default
- [x] API keys per client with roles: write, delete, read_masked, read_full
- [x] Blind index: exact-match search on indexed email, phone and card fields, own `search` role
- [x] Audit log: every create, reveal, search and delete, written before the data leaves
- [x] Batch create, atomic up to 1000 objects, and batch reveal with per-object audit
- [x] OpenAPI spec, served at /openapi.json and tested against the routes; Go client package
- [x] Master key from a file or a command; rotation by re-wrapping, while serving
- [x] Wrapping key in a key service: Vault and OpenBao transit, AWS KMS; migration by rotation
- [x] Subjects: `_subject` on objects, list and erase everything about one person in one call
- [x] Per-client reveal budget: full reveals and searches rate-limited, masked reads free
- [x] Two database roles: `sealbox migrate` with the owner, servers with a role whose audit log is append-only
- [x] Hardening: audit entries to stdout for shipping, no core dumps on Linux, client certificates for the API
- [x] `sealbox reindex`: rebuild the blind index for existing objects under a changed schema
- [x] Prometheus metrics on a separate address
- [x] Search pagination with an `after` cursor
- [x] Signed releases with an SBOM on every tag
- [x] Batch reads through a key service unwrap 500 keys per round trip

## Design rules

1. No custom cryptography. Only `golang.org/x/crypto` and the standard library.
2. Every change to `internal/envelope` or the store ships with a test.
3. One way to do each thing. No plugin system, no framework, no ORM.
4. Secrets never reach logs, error messages or panics.
5. Behaviour is configured, not compiled: schemas and policies are data.

## Layout

```
cmd/sealbox/                entry point, config from env, TLS
client/                     Go client for the API
internal/api/               HTTP handlers, clients and roles, input limits, openapi.json
internal/envelope/          per-object keys wrapped under the master key, or by a key service
internal/metrics/           request counters in the Prometheus text format
internal/schema/            field types, validation, masks; loaded from SEALBOX_SCHEMA
internal/store/             Postgres; delete nulls the wrapped key, the row stays
internal/store/migrations/  numbered SQL files, applied once each at startup
```

## Dependencies

Direct runtime dependencies, all under permissive licenses. CI fails if any dependency, direct or transitive,
carries a license outside Apache-2.0, BSD, MIT or ISC.

| Module | License | Used for |
|---|---|---|
| golang.org/x/crypto | BSD-3-Clause | XChaCha20-Poly1305 |
| github.com/jackc/pgx/v5 | MIT | Postgres driver |
| github.com/jackc/tern/v2 | MIT | SQL migrations with an advisory lock |
| golang.org/x/time | BSD-3-Clause | per-client rate limiting |

The full transitive list: `go run github.com/google/go-licenses@v1.6.0 report ./...`.
Builds with `-tags awskms` add the AWS SDK for Go v2, Apache-2.0, and its modules.

## Development

```sh
docker compose up -d postgres
SEALBOX_TEST_DATABASE_URL=postgres://sealbox:sealbox@localhost:5430/sealbox?sslmode=disable go test -race ./...
```

Store tests are skipped when `SEALBOX_TEST_DATABASE_URL` is not set. CI runs them against a Postgres service.
They use a fixed test master key, so a database that has already been used by the quickstart server, or was left mid-rotation
by a killed run, refuses to open. Reset it with `docker compose down -v`.

## License

Apache-2.0. See [LICENSE](LICENSE).
