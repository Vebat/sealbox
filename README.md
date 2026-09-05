# sealbox

Encrypted vault for personal data. Delete the key, shred the data.

> **Status: pre-alpha, not audited.** Nothing here has been reviewed by anyone but the author. Do not put real data in it yet.

## The problem

GDPR gives people the right to have their data erased. Your backups are kept for years.
PCI DSS and similar regimes audit every system that can see a card number, a passport or a diagnosis.
Every table that holds personal data widens the blast radius of the next leak.

sealbox takes personal data out of your database. Your application stores a token; sealbox stores the
ciphertext, encrypted under a key that exists only for that one object. Deleting the object deletes its key,
so every copy of the ciphertext in every backup and replica becomes unreadable at the same moment.
This is crypto-shredding, and it is the only practical way to honour an erasure request when backups outlive it.

## API

Every request carries `Authorization: Bearer <key>`. An object is a JSON object up to 1 MiB.
Reads are masked unless the caller asks for `reveal=full` and holds the role for it.

Keys belong to named clients with explicit roles, declared in `SEALBOX_KEYS_FILE` (see [keys.example.json](keys.example.json)).
`SEALBOX_API_KEY` adds one client named `default` with every role, for development.

| Role | Allows |
|---|---|
| `write` | `POST` objects |
| `read_masked` | `GET` with masks applied |
| `read_full` | `GET ?reveal=full`, the plaintext |
| `delete` | `DELETE`, the crypto-shred |
| `search` | `POST .../search`, ids by an indexed value |

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

Search takes exactly one indexed field and finds objects whose value is equal after normalization.
It is exact match only: you can find a record by a value you already know in full, you cannot browse.
Ranges, prefixes and free text belong in your own database, on fields that are not personal data.

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
- Masks are fixed per type. What they keep, the email domain and the last four digits, is visible to every holder of a `read_masked` key by design.
- `index: true` makes a field searchable. sealbox stores an HMAC-SHA256 of the normalized value under a key derived from the master key, never the value.
  A database dump shows which records share a value, not what it is, and cannot be used to test guesses without the master key.
- Validation errors name the field, never the submitted value.
- The schema is read at startup. Change the file, restart the process. Adding `index` to a field indexes new objects only; re-indexing existing ones is not built yet.

## Audit log

Every successful action is written to the `audit_log` table: which client did what, to which object, when.
For a search, the field that was queried. Never a value, never a hash.
A reveal is logged before the data is returned: if the log cannot be written, the request fails and nothing is revealed.

| Action | Written when |
|---|---|
| `create` | an object was stored |
| `reveal_masked` | a masked read |
| `reveal_full` | a plaintext read |
| `search` | a lookup by an indexed field |
| `delete` | a crypto-shred |

Read it with SQL. Everything about one person:

```sql
SELECT at, client, action FROM audit_log WHERE object_id = 'tok_...' ORDER BY at;
```

sealbox only inserts into this table. It does not yet separate the migration owner from the runtime user,
so whoever holds the database credentials can still delete rows. If you need tamper evidence today,
ship the table to storage the application cannot write to.

## Transport

sealbox terminates TLS itself: set `SEALBOX_TLS_CERT` and `SEALBOX_TLS_KEY`. Without them it refuses to listen on
anything but a loopback address, unless `SEALBOX_INSECURE_HTTP=1` says TLS is terminated in front of it. Think
before doing that: whatever terminates TLS sees personal data in request bodies, and most ingresses log bodies on error.

Connect to Postgres with `sslmode=verify-full`. sealbox warns at startup when it sees `sslmode=disable`.

## What it protects against

- A dump of the database, or a stolen backup: ciphertext only, per-object keys wrapped under a master key that is never stored next to the data.
- An insider with database access: same.
- Personal data leaking through application logs, analytics or search indexes: the application only ever holds tokens.
- Erasure requests against long-lived backups: crypto-shredding.

It does **not** protect against a compromised sealbox process, a stolen master key, or an application
that decrypts a value and leaks it itself. Read [THREAT_MODEL.md](THREAT_MODEL.md) before relying on it.

## Compared to

| | sealbox | HashiCorp Vault / OpenBao | Skyflow, Evervault, Basis Theory | Google Tink |
|---|---|---|---|---|
| Open source | Apache-2.0 | BUSL / MPL | no | yes |
| Self-hosted | one binary + Postgres | yes | no | library only |
| Stores the data (tokenization) | yes | Enterprise only | yes | no |
| Per-object key, crypto-shred | yes | no | vendor-specific | you build it |
| Masking, roles, audit log | planned | partial | yes | no |

## Quickstart

```sh
printf 'SEALBOX_MASTER_KEY=%s\nSEALBOX_API_KEY=%s\n' "$(openssl rand -base64 32)" "$(openssl rand -base64 32)" > .env
docker compose up --build
```

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

## Roadmap

Each item is one release.

- [x] Envelope encryption: XChaCha20-Poly1305, fresh key per object, ciphertext bound to the object id
- [x] Postgres store; delete destroys the wrapped key, with a test that proves the ciphertext is dead
- [x] HTTP API: create, get, delete; one API key; TLS built in, plaintext only on loopback
- [x] Collection schemas from a JSON file; email, phone, card and string types; masked reads by default
- [x] API keys per client with roles: write, delete, read_masked, read_full
- [x] Blind index: exact-match search on indexed email, phone and card fields, own `search` role
- [x] Audit log: every create, reveal, search and delete, written before the data leaves
- [x] Batch create, atomic up to 1000 objects, and batch reveal with per-object audit
- [ ] OpenAPI spec and a generated client
- [ ] Master key from a KMS, key rotation

## Design rules

1. No custom cryptography. Only `golang.org/x/crypto` and the standard library.
2. Every change to `internal/envelope` or the store ships with a test.
3. One way to do each thing. No plugin system, no framework, no ORM.
4. Secrets never reach logs, error messages or panics.
5. Behaviour is configured, not compiled: schemas and policies are data.

## Layout

```
cmd/sealbox/                entry point, config from env, TLS
internal/api/               HTTP handlers, clients and roles, input limits
internal/envelope/          per-object keys wrapped under the master key
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

The full transitive list: `go run github.com/google/go-licenses@v1.6.0 report ./...`.

## Development

```sh
docker compose up -d postgres
SEALBOX_TEST_DATABASE_URL=postgres://sealbox:sealbox@localhost:5432/sealbox?sslmode=disable go test -race ./...
```

Store tests are skipped when `SEALBOX_TEST_DATABASE_URL` is not set. CI runs them against a Postgres service.

## License

Apache-2.0. See [LICENSE](LICENSE).
