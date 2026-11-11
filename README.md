<h1 align="center">go-codepair</h1>

<div align="center">

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.27.3+-00ADD8?logo=go&logoColor=white)](go.mod)

</div>

---

Pair two devices on a LAN with a short human-typed code and an authenticated key exchange. Package `codepair`, module `github.com/Totative/go-codepair`.

Two devices that share a network but no trust can be paired by a person reading a short code from one and typing it
into the other. This package is the cryptographic core of that exchange: it mints the code and runs
[CPace](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/), a password-authenticated key exchange, so the two
devices agree on a key only if they hold the same code, and an attacker on the wire gets one guess per run.

## Quick start

```bash
go get github.com/Totative/go-codepair
```

A worked example and the contracts: [HUMANS.md](HUMANS.md).

## Features

- Codes: `NewCode` draws each character uniformly from a caller-chosen alphabet, and `Normalize` folds a typed code
  into the form both sides use, so case and separators never matter. `Validate` enforces a 32-bit entropy floor.
  `NewJoiner` and `NewHost` refuse a code that is not exactly `CodeLength` characters from `Alphabet` (`ErrCode`).
- Key exchange: `Joiner` and `Host` run CPace (draft-irtf-cfrg-cpace-21, ristretto255, SHA-512), bind the protocol
  label and both ids and display names, and confirm the key in both directions before they return a `Pairing`.
- Peer key: the long-term key is HKDF-SHA-512 of the exchange's session key, so it never depends on a guessable value.
- Rate limiting: `NewLimiter` returns an error unless its bounds are positive. `Limiter` is charged once per run,
  locks a remote out after a set number of failures, and reports when failures in all have reached the point where
  the caller should drop the code.

## Documentation

| Doc | Audience |
| --- | --- |
| [HUMANS.md](HUMANS.md) | Running and using the package |
| [AGENTS.md](AGENTS.md) | Internals, invariants, and why |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Process — commits, tests, docs |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |

## License

Apache-2.0, see [LICENSE](LICENSE). © 2026 Damon Blais.
