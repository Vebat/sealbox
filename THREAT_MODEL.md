# Threat model

This document says what sealbox defends against and what it does not.
If a claim in the README is not backed by a line here, the README is wrong.

## Assets

1. **Plaintext personal data** submitted by the application.
2. **The master key** (`SEALBOX_MASTER_KEY`). Wraps every per-object key.
3. **Per-object keys (DEKs)**, stored wrapped next to the ciphertext.
4. **API credentials** that allow reveal.
5. **The audit log**: who revealed what, when. Holds client names and object ids, never values.

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
- API keys are bearer secrets, one per client, each with explicit roles. A client that only needs masked reads never holds a key that can reveal plaintext. Keys are compared in constant time. The keys file stores them in plaintext: protect it like the master key.

## Protects against

| Threat | Defence |
|---|---|
| Database dump, stolen backup, leaked replica | Only ciphertext and wrapped DEKs are stored. Without the master key nothing opens. |
| Insider with SQL access | Same as above. |
| Ciphertext moved from one record to another | Every ciphertext is bound to its object id via AEAD associated data; it fails to open elsewhere. |
| Erasure request while backups still exist | Delete destroys the wrapped DEK. All copies of the ciphertext become unrecoverable. |
| Personal data in application logs, search indexes, analytics | The application never holds plaintext unless it explicitly reveals it. |
| Bulk exfiltration through the reveal endpoint | `read_full` is granted per client, so most keys can only see masks. Every reveal is logged before the data is returned. Planned: rate limits on full reveal. |
| A reveal that leaves no trace | The audit entry is written first; if it fails, the request fails and nothing is returned. |
| Nonce reuse | Random 24-byte nonces (XChaCha20) and a fresh key per object. |
| Testing guesses against the search index from a dump | The blind index is HMAC-SHA256 under a key derived from the master key with HKDF. Without the master key a dump cannot confirm a guess. |
| Shredded objects still findable by search | Delete removes the object's index rows in the same transaction that destroys its key. |

## Does not protect against

| Threat | Why |
|---|---|
| Compromise of the sealbox process or host | The master key is in RAM. Run it isolated, with the least privilege you can. |
| Theft of the master key from the environment, secret store or KMS | Whoever has it has everything. Guard it like a root credential. |
| An application that reveals a value and then leaks it | sealbox limits who can reveal, not what they do afterwards. |
| Loss of the master key | Every stored value is gone. Back the key up outside the database, and test the restore. |
| A malicious or buggy sealbox build | Verify releases. Signed builds and an SBOM are on the roadmap; a third-party audit has not happened. |
| Traffic analysis | Object sizes and access patterns are visible to the database and the network. |
| Equality leaking through the blind index | A dump shows which records share an indexed value, not what it is. Hashes are separated per collection and field, so the same value in two fields does not link them. Index only what you must search. |
| Membership probing through search | Search confirms whether a value you already hold exists. It needs the `search` role and is logged; rate limits are planned. |
| Tampering with the audit log by whoever holds the database credentials | sealbox only inserts, but its database user owns the table. A separate migration role and external log shipping are planned. |
| Side channels on shared hardware | Out of scope. |

## Assumptions

- The operator generates the master key with a CSPRNG and stores it outside the database.
- Postgres is reachable only from sealbox.
- Clocks are roughly correct (matters for the audit log, later).
- `golang.org/x/crypto` and the Go standard library are correct. sealbox contains no cryptographic primitives of its own.
