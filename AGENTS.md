# AGENTS.md

Package `codepair` is the cryptographic core of pairing two devices with a short human-typed code: code minting and
normalisation, the CPace password-authenticated key exchange with key confirmation, and the guess limiter. Callers
import it to run a pairing handshake over a transport they already have; it imports the standard library and
`github.com/gtank/ristretto255` only, and never a consumer's package, so it carries no transport, storage, session,
or event names of its own.

## Gate

`gate` is the command. Each override in `.gate.toml` is there because a runner
cannot resolve that check from PATH.

## Shape

- No default names a protocol. `Config` has no defaults and `Validate` refuses a zero field, because a package cannot
  know a caller's protocol string and a wrong default would derive keys under a label the other side never checks.
- The handshake is CPace (draft-irtf-cfrg-cpace-21) over ristretto255 and SHA-512, initiator-responder, with the
  protocol label as channel identifier and an empty session id. `cpace.go` keeps the draft's function names so each
  can be read against the text, and `cpace_test.go` pins every intermediate value of the draft's vectors.
- `Normalize` runs inside `NewJoiner` and `NewHost`, so a caller that stored a normalised copy and one that stored
  the raw code still agree; an exported shortcut around it would let the two drift.
- Ids and display names travel as the draft's associated data, `lv_cat(id, name)`, and the receiver reads the peer's
  back out of it. Length-value encoding is canonical (`splitPair` rejects anything else), so no two field tuples
  share bytes.
- K is never exposed. The stored key is HKDF over ISK, and a `Pairing` is returned only after the peer's
  confirmation tag verified: no error path returns a key.
- The joiner answers only after verifying the host's tag, so a host without the code obtains nothing to test other
  guesses against. The host's reply is the one guess an impostor joiner gets, which is why `Host.Accept` charges the
  `Limiter` for the remote before it replies.
- `CodeLength`, `Alphabet` are caller policy, bounded below only by `MinCodeBits` and the alphabet rules in
  `Validate`; the package does not decide how long a code lives.
- `Limiter` holds its own mutex and knows nothing about codes, sessions or clocks it does not receive. `now` is a
  parameter so a test can move time without sleeping, and `Charge` checks and counts under one lock so runs racing
  each other cannot jointly pass the limit. Remotes are keyed by IP, with IPv6 grouped by /64.
- `Limiter.Refund` never shortens a lockout and never drives a count below zero. A refund belongs to a success; it
  cannot undo a lockout another guess earned.
- Nothing here touches a socket, a file, or a global. The package has no `init`, no package-level mutable state, and
  no goroutines, so a caller decides when work happens.

## Files

| File | Holds |
| --- | --- |
| `doc.go` | The package clause and its one-line summary. |
| `codepair.go` | `Config`, its `Validate`, `NewCode` and `Normalize`. |
| `cpace.go` | The CPace functions for ristretto255 and SHA-512, length-value encoding, key-confirmation tags. |
| `pairing.go` | `Joiner`, `Host` and `Pairing`: the exported handshake. |
| `limiter.go` | `Limiter`: the per-remote lockout, the global failure count, and their refund. |
