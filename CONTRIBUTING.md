# Contributing

Keep changes small, tested and municipality-neutral. Read
[docs/DESIGN.md](docs/DESIGN.md) first; it is normative. A change to a wire
format, hash, circuit constraint or contract interface starts with an update
to DESIGN.md and, where it is a real decision, an ADR in `docs/adr/`.

## Before opening a pull request

```sh
npm ci
npm run verify
```

`verify` runs the type check, lint, the Node test suite, the Noir tests, the
Foundry tests and the artifact reproducibility check. A change to the circuit
must regenerate the artifacts and the Solidity verifier
(`npm run circuit:build`, `npm run verifier:generate`, `npm run fixtures:build`)
and commit them together.

## Rules

- Add no personal data: no names, addresses, birth dates, document numbers,
  real Nostr keys, wallet addresses of residents, or contact details.
- Add no credentials, deployment manifests or operations receipts.
- Do not copy code, text or assets from differently licensed products. To
  integrate another system, reimplement its public interface from its
  specification.
- Tests are deterministic and isolated, and test behaviour rather than
  wiring.

By contributing you agree that your contribution is licensed under the MIT
License of this repository.
