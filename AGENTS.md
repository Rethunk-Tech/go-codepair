# AGENTS.md

Package `codepair` is the cryptographic core of pairing two devices with a short human-typed code: code minting and
normalisation, the X25519 exchange's key derivation, the transcript, the two proofs, and the guess limiter. Callers
import it to run a pairing handshake over a transport they already have; it imports only the standard library, and
never a consumer's package, so it carries no transport, storage, session, or event names of its own.

## Gate

`gate` is the command. Each override in `.gate.toml` is there because a runner
cannot resolve that check from PATH.

## Shape

- No default names a protocol. `Config` has no defaults and `Validate` refuses a zero field, because a package cannot
  know a caller's protocol string and a wrong default would derive keys under a label the other side never checks.
- `Keys` is the only path from a code to bytes. `Normalize` runs inside it, so a caller that stored a normalised copy
  and a caller that stored the raw one still agree; adding an exported shortcut around it would let the two drift.
- `Transcript` is the only path that lays out the signed fields. Both sides must build identical bytes, so the field
  order, the separators, and the placement of the protocol live in one function, not in each caller.
- The role string in `Proof` stays a separate argument. One side signing with the other's role would let a captured
  proof be replayed back at its sender.
- `Verify` wraps `hmac.Equal` and nothing else. A plain `bytes.Equal` leaks how many leading bytes were right.
- `Iterations`, `CodeLength`, `Alphabet` are caller policy, fixed at pairing time by whatever both peers agreed on;
  only `Keys` reads `Iterations`, and only `NewCode` reads the other two. Nothing in the package bounds them: a
  library does not get to decide how long another product's code lives or how many characters it has.
- `Limiter` holds its own mutex and knows nothing about codes, sessions or clocks it does not receive. `now` is a
  parameter so a test can move time without sleeping, and the charge happens before the check so guesses racing each
  other cannot outnumber the limit.
- `Limiter.Refund` never shortens a lockout and never drives a count below zero. A refund belongs to a success; it
  cannot undo a lockout another guess earned.
- Nothing here touches a socket, a file, or a global. The package has no `init`, no package-level mutable state, and
  no goroutines, so a caller decides when work happens.

## Files

| File | Holds |
| --- | --- |
| `doc.go` | The package clause and its one-line summary. |
| `codepair.go` | `Config`, its `Validate`, `NewCode`, `Normalize`, `Keys`, `Transcript`, `Proof` and `Verify`. |
| `limiter.go` | `Limiter`: the per-remote lockout, the global failure count, and their refund. |
