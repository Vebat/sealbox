# Security policy

## Status

sealbox is pre-alpha, maintained by one person, and has **not** been audited by a third party.
Treat every claim in the README and the threat model as unverified until it is.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository ("Security" tab, "Report a vulnerability").
Do not open a public issue for anything that could be exploited.

Reports are answered on a best-effort basis, usually within a week. Confirmed issues are fixed before they are discussed publicly.

## Scope

In scope: anything in this repository that lets an attacker read, modify or un-shred data they are not authorised for, or recover key material.

Out of scope: issues that require a compromised host, a stolen master key, or a malicious operator. See [THREAT_MODEL.md](THREAT_MODEL.md).
