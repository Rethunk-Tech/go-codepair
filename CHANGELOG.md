# Changelog

Notable changes to `go-codepair`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-11-11

### Added

- A password-authenticated key exchange: `Config.NewJoiner` and `Config.NewHost` run CPace
  (draft-irtf-cfrg-cpace-21, ristretto255 with SHA-512), bind the protocol label and both devices' ids and display
  names, confirm the key in both directions, and return a `Pairing` holding the peer key and the peer's identity only
  after both confirmations verify. An attacker who does not hold the code gets one guess per run.
- `ErrMessage` and `ErrConfirmation` to tell a malformed message from a wrong code, and `ErrCode` when the typed
  code is not exactly `Config.CodeLength` characters from `Config.Alphabet`.
- `MinCodeBits`: `Validate` now refuses codes under 32 bits, alphabets with repeated, non-ASCII or non-printable
  characters, and characters `Normalize` rewrites.

### Changed

- `Limiter.Charge` returns `(locked, burned)` and counts only a guess it serves, so checking and charging are one
  call. `Limiter.Locked` is gone. A caller charges once per run, before `Host.Accept`. `NewLimiter` returns
  `(*Limiter, error)` and refuses a non-positive bound. `Refund` is a no-op unless that remote has an outstanding
  charge.
- `Config.Iterations` is gone; the code is no longer stretched, because CPace does not expose it to offline guessing.
- `Config.Keys`, `Transcript`, `Proof` and `Verify` are replaced by the types above.

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

[Unreleased]: https://github.com/Totative/go-codepair/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Totative/go-codepair/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Totative/go-codepair/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Totative/go-codepair/releases/tag/v0.1.0
