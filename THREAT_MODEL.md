# Threat model

This document says what sealbox defends against and what it does not.
If a claim in the README is not backed by a line here, the README is wrong.

## Assets

1. **Plaintext personal data** submitted by the application.
2. **The master keys**. The current one wraps every new per-object key; previous ones, during a rotation, still open old rows.
3. **Per-object keys (DEKs)**, stored wrapped next to the ciphertext, each tagged with the fingerprint of the master key that wrapped it.
4. **The blind-index key**, a service key stored wrapped in the same way.
5. **API credentials** that allow reveal.
6. **The audit log**: who revealed what, when. Holds client names and object ids, never values.

## Trust boundaries

```
 application --HTTP--> sealbox process --SQL--> Postgres
      |                      |                     |
   trusted             trusted, holds          untrusted:
   to hold tokens      master key in RAM       ciphertext only
```

- The application is trusted with whatever it is allowed to reveal, and nothing more.
- The sealbox process is fully trusted. It holds the master key in memory.
- The database, its backups, replicas and anyone with access to them are untrusted.
- sealbox terminates TLS itself when given a certificate and refuses plaintext on non-loopback addresses unless explicitly told TLS is handled in front of it. Terminating TLS at an ingress that logs request bodies puts personal data in those logs; keep TLS end to end.
- API keys are bearer secrets, one per client, each with explicit roles. A client that only needs masked reads never holds a key that can reveal plaintext. Keys are compared in constant time. The keys file stores them in plaintext: protect it like the master key. With `SEALBOX_TLS_CLIENT_CA` a stolen key is useless without a client certificate as well.

## Protects against

| Threat | Defence |
|---|---|
| Database dump, stolen backup, leaked replica | Only ciphertext and wrapped DEKs are stored. Without the master key nothing opens. |
| Insider with SQL access | Same as above. |
| Ciphertext moved from one record to another | Every ciphertext is bound to its object id via AEAD associated data; it fails to open elsewhere. |
| Erasure request against the live database, replicas and later backups | Delete destroys the wrapped DEK. The ciphertext cannot be opened from this database or from any backup taken after the delete. |
| Personal data in application logs, search indexes, analytics | The application never holds plaintext unless it explicitly reveals it. |
| Bulk exfiltration through the reveal endpoint | `read_full` is granted per client, so most keys can only see masks. Every reveal is logged before the data is returned; batch reveal is capped at 1000 objects and logged per object. Each client has a reveal budget: full reveals, per object, and searches beyond it are refused with 429. |
| A reveal that leaves no trace | The audit entry is written first; if it fails, the request fails and nothing is returned. Creates and deletes commit with their entry in one transaction. |
| A compromised server rewriting the audit log | Run the servers as the runtime role: it can append to the log and nothing else. |
| Nonce reuse | Random 24-byte nonces (XChaCha20) and a fresh key per object. |
| Testing guesses against the search index from a dump | The blind index is HMAC-SHA256 under a random index key that is stored wrapped by the master key. Without the master key a dump cannot confirm a guess. |
| Reading a service key through the object API | Service keys and objects are sealed in separate AAD namespaces, and ids are validated: a keys row copied into the objects table does not open. |
| Shredded objects still findable by search | Delete removes the object's index rows in the same transaction that destroys its key. |
| Master key sitting in the environment | It can come from a file or from a command, so a secret store hands it over at startup. |
| Master key sitting in the process at all | With `SEALBOX_KMS=transit` or `awskms` the wrapping key stays in the key service; sealbox only ever holds per-object keys, and only while using them. |
| A master key that must be retired | Several keys load at once; `sealbox rotate` re-wraps every key in pages while serving. Rotation never writes a key back into a row shredded meanwhile. |

## Does not protect against

| Threat | Why |
|---|---|
| Compromise of the sealbox process or host | With a local master key it is in RAM and the attacker has everything. With a key service (`SEALBOX_KMS`) the process holds no master key: the attacker can only unwrap keys while present, one call each, logged and revocable at the service. Run sealbox isolated, with the least privilege you can. |
| Theft of the master key from the environment, secret store or KMS | Whoever has it has everything. Guard it like a root credential, and rotate as soon as theft is suspected. |
| Data exposed before a rotation | Rotation re-wraps keys, it does not re-encrypt. The old key together with a dump taken while it was in use still opens those rows. |
| A backup taken before an erasure, held with the master key that was current then | The backup carries the wrapped DEK next to the ciphertext. Rotate the master key and destroy the retired one; every backup older than that rotation is then dead for every object erased before it. Schedule rotations to match your erasure promises. |
| An application that reveals a value and then leaks it | sealbox limits who can reveal, not what they do afterwards. |
| Loss of the master key | Every stored value is gone. Back the key up outside the database, and test the restore. |
| A malicious or buggy sealbox build | Verify releases. Signed builds and an SBOM are on the roadmap; a third-party audit has not happened. |
| Traffic analysis | Object sizes and access patterns are visible to the database and the network. |
| Equality leaking through the blind index | A dump shows which records share an indexed value, not what it is. Hashes are separated per collection and field, so the same value in two fields does not link them. Index only what you must search. |
| Membership probing through search | Search confirms whether a value you already hold exists. It needs the `search` role, is logged, and spends the client's reveal budget, so probing a list of phone numbers runs at the budget's pace and shows in the log. |
| Tampering with the audit log by whoever holds the owner credentials | With two roles the servers can only append; the owner role that runs migrations can still rewrite the log. `SEALBOX_AUDIT_STDOUT=1` sends a copy of every entry to stdout for shipping elsewhere. |
| Side channels on shared hardware | Out of scope. |

## Assumptions

- The operator generates the master key with a CSPRNG and stores it outside the database.
- Postgres is reachable only from sealbox.
- Audit timestamps come from the Postgres clock.
- `golang.org/x/crypto` and the Go standard library are correct. sealbox contains no cryptographic primitives of its own.
