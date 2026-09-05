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

Every request carries `Authorization: Bearer <SEALBOX_API_KEY>`. An object is any JSON object up to 1 MiB.

```http
POST /v1/collections/customers/objects
{ "email": "ivan@example.com", "passport": "4510 123456" }
-> 201 { "id": "tok_9f3a..." }

GET /v1/collections/customers/objects/tok_9f3a...
-> 200 { "email": "ivan@example.com", "passport": "4510 123456" }

DELETE /v1/collections/customers/objects/tok_9f3a...
-> 204, the object's key is destroyed; its ciphertext is now noise
```

Planned, not built yet:

```http
GET /v1/collections/customers/objects/tok_9f3a...?reveal=masked
-> { "email": "i***@example.com", "passport": "45** ******" }

POST /v1/collections/customers/search
{ "email": "ivan@example.com" }
-> { "ids": ["tok_9f3a..."] }
```

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
curl -s -X DELETE -H "Authorization: Bearer $KEY" localhost:8080/v1/collections/customers/objects/tok_...
```

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
- [ ] Collection schemas, field types, masks
- [ ] API key roles: write, read masked, read full
- [ ] Blind index for exact-match search on email and phone
- [ ] Append-only audit log of every reveal
- [ ] Batch import and batch reveal
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
internal/api/               HTTP handlers, bearer auth, input limits
internal/envelope/          per-object keys wrapped under the master key
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
