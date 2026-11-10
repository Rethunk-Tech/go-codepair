<h1 align="center">go-codepair</h1>

<div align="center">

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.27.3+-00ADD8?logo=go&logoColor=white)](go.mod)

</div>

---

Pair two devices on a LAN with a short human-typed code and an authenticated key exchange. Package `codepair`, module `github.com/Totative/go-codepair`.

Two devices that share a network but no trust can be paired by a person reading a short code from one and typing it
into the other. This package is the cryptographic core of that exchange: it mints the code, derives the two secrets
from it, and proves to each side that the other knows the code, so a device that guesses wrong learns nothing about
the key being agreed.

## Quick start

```bash
go get github.com/Totative/go-codepair
```

A worked example and the contracts: [HUMANS.md](HUMANS.md).

## Features

- Codes: `NewCode` draws each character uniformly from a caller-chosen alphabet, and `Normalize` folds a typed code
  into the form both sides hash, so case and separators never matter.
- Key derivation: `Keys` stretches the low-entropy code into a proof key with PBKDF2-SHA256 and derives the
  long-term peer key with HKDF-SHA256 from the shared secret alone, so the stored key cannot be guessed offline.
- Transcript: `Transcript` binds the protocol, both public keys, and both ids and display names, so a relay in the
  middle cannot rename a device and still pass.
- Proofs: `Proof` signs the transcript and the shared secret under the peer's role, and `Verify` compares in
  constant time.
- Rate limiting: `Limiter` counts guesses before they are checked, locks a remote out after a set number of
  failures, and reports when failures in all have reached the point where the caller should drop the code.

## Documentation

| Doc | Audience |
| --- | --- |
| [HUMANS.md](HUMANS.md) | Running and using the package |
| [AGENTS.md](AGENTS.md) | Internals, invariants, and why |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Process — commits, tests, docs |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |

## License

Apache-2.0, see [LICENSE](LICENSE). © 2026 Rethunk.Tech, LLC.
