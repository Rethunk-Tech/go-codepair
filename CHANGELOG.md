# Changelog

Notable changes to `go-codepair`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-10

### Changed

- The module path is now `github.com/Totative/go-codepair`; update imports and the `require` line in `go.mod`.
- The licence is now Apache-2.0.

### Added

- Each release tarball carries a signed build provenance and an SBOM attestation; check one with `gh attestation verify <file> --owner Totative`.

## [0.1.0] - 2026-11-08

### Added

- Code generation from a caller-chosen alphabet, and normalisation of the code a user types.
- Key derivation from the X25519 shared secret: a code-keyed proof key and a long-term peer key.
- A transcript that binds both public keys, ids and display names, and the two role-separated proofs over it.
- A guess limiter with a per-remote lockout and a global failure count the caller can act on.

[Unreleased]: https://github.com/Totative/go-codepair/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Totative/go-codepair/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Totative/go-codepair/releases/tag/v0.1.0
