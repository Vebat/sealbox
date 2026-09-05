# Security policy

## Status

sealbox is pre-alpha and has **not** been audited by a third party. Treat every claim as unverified until it is.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository ("Security" tab, "Report a vulnerability").
Do not open a public issue for anything that could be exploited.

You will get an acknowledgement within 7 days. Fixes for confirmed issues are released before any public discussion.

## Scope

In scope: anything in this repository that lets an attacker read, modify or un-shred data they are not authorised for, or recover key material.

Out of scope: issues that require a compromised host, a stolen master key, or a malicious operator. See [THREAT_MODEL.md](THREAT_MODEL.md).
