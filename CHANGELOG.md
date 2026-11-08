# Changelog

Notable changes to `go-codepair`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Code generation from a caller-chosen alphabet, and normalisation of the code a user types.
- Key derivation from the X25519 shared secret: a code-keyed proof key and a long-term peer key.
- A transcript that binds both public keys, ids and display names, and the two role-separated proofs over it.
- A guess limiter with a per-remote lockout and a global failure count the caller can act on.

[Unreleased]: https://github.com/Rethunk-Tech/go-codepair/commits/main
