# Security policy

## Status

This code has **not been audited**. It is suitable for advisory civic
participation pilots, not for binding elections. Read
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before deploying it.

## Reporting a vulnerability

Please report privately through GitHub's private vulnerability reporting for
this repository (**Security → Report a vulnerability**). Do not open a public
issue for anything that could affect residents, issuers or poll integrity.

Include what you found, how to reproduce it, and the impact you expect. We
aim to acknowledge reports within seven days and to agree on a disclosure
date with you.

## Scope

- the eligibility issuer and its HTTP endpoints (`src/issuer`, `src/http.ts`,
  `src/server.ts`);
- eligibility adapters (`src/adapters`);
- the advisory participation lane (`src/vote`);
- the Noir circuit (`circuits/membership_vote`) and the contracts
  (`contracts/src`).

Deployments operated by municipalities or third parties are out of scope;
report those to their operators.

## Handling secrets

The issuer's Ed25519 signing key and RPC credentials are runtime
configuration loaded by reference (`ISSUER_SIGNING_KEY_FILE`,
`ISSUER_SIGNING_KEY_SEED_HEX`, adapter RPC variables). They never belong in a
policy file, the database, a commit or a client bundle.
