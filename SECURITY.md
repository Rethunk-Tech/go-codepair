# Security

## The code is low entropy, on purpose

An eight-character code from a 31-character alphabet is about 2^39.6 possibilities: few enough to read aloud, so the
package assumes an attacker can guess. Two things bound that. Offline, after recording a handshake, each guess costs
`Config.Iterations` of PBKDF2-SHA256, and the code is only useful for as long as the caller honours it, so the
attacker's rate is set by that cost times the code's lifetime, not by a network round trip. Online, `Limiter` is the
bound: it counts a guess before it is checked, locks a remote out after its failures, and reports `burned` once
failures in all reach the caller's limit, at which point the caller should drop the code.

Offline guessing is why a caller should not keep a code open longer than a person needs to type it, and why
`Iterations` is the caller's decision rather than a library default.

The transcript binds both public keys, both device ids, and both display names. A relay between the two devices
therefore cannot rename a device, swap one device's key for its own, or replay half of another pairing's exchange
without one of the proofs failing.

## Supported versions

The latest tagged release. There are no long-lived release branches, so a fix ships in the next tag
rather than being backported.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository (Security → Report a
vulnerability). It stays private until a fix ships.

Please do not open a public issue for a suspected vulnerability first.

## What is in scope

- The code a user types, through `Normalize` and `Keys`: any bytes, any length, any encoding. `Normalize` must not
  panic or allocate without bound, and `Keys` must produce the same key for a code however it was separated or
  capitalised, never a different one.
- A peer's public key and the two devices' ids and names, through `Transcript` and `Proof`: any bytes, and strings
  long enough to matter. `Transcript` must stay total and length-unambiguous, so that no two distinct field tuples
  produce the same bytes and a relay cannot shift a name into an id.
- A proof from the other side, through `Verify`: any bytes, empty included. It must report unequal without panicking
  and without taking time that depends on where the two differ.
- The remote identifier and clock a caller passes to `Limiter.Locked`, `Charge` and `Refund`: any string, and a clock
  that moves backwards. None may panic or leave the counts negative.
- The `Config` a caller builds, through `Validate`: a zero or negative field is refused rather than defaulted, so no
  code is minted and no key is derived under a label nobody agreed on.

## What is out of scope

- The transport, the X25519 key exchange that produces the shared secret, and the lifetime of an open code are the
  caller's. This package never sees a wire, a clock, or a session, so a caller that ignores `Config.Iterations` or
  honours a code forever has weakened its own pairing.
- A short code is low entropy by design. An attacker who records a handshake can guess offline, one `Iterations` of
  PBKDF2 per guess, so a code's exposure is bounded by that cost times how long it is honoured; an attacker who
  guesses online is bounded by whatever `Limiter` bounds are passed, and by the caller acting on `Charge`'s `burned`.
- A caller may show the code grouped, in lower case, or read it aloud; `Normalize` accepts that. It is intended that
  `Normalize` leaves every other character alone, including characters outside the alphabet, which then fail.
- A device that completes pairing is trusted by whoever stored the key. This package proves knowledge of the code
  and binds the transcript; it does not decide which devices should pair, what a paired device may do, or when a
  stored key expires.
- The code itself is meant to be visible: the user reads it off one screen and types it into another. Anyone who can
  see that screen already has it.
