# Security

## What an attacker can do

The code is low entropy on purpose: eight characters from a 31-character alphabet is about 2^39.6 possibilities,
and `Config.Validate` refuses anything under 32 bits. The handshake is CPace, a balanced password-authenticated key
exchange, so the code is never testable against recorded or computed data.

- A passive attacker, one who records the whole exchange, learns nothing it can test a code guess against: the
  messages are group elements masked by secret scalars, and testing a guess needs one of those scalars.
- An active attacker gets exactly one guess per protocol run. Pretending to be the host, it can test one code per
  joiner run, because the joiner answers only after the host's confirmation verifies. Pretending to be the joiner,
  it can test one code per run, because the host's reply is the only thing it receives. A wrong guess yields no
  data that rules out any other code, and no key.
- Guesses against the host are counted by `Limiter`, whose global burn count is the only hard cap (the per-remote
  lock is a rate limit). The caller must call `Limiter.Charge` before `Host.Accept` and refuse when it reports
  locked or burned. Guesses against the joiner by a rogue host are one per run the user starts and are not counted
  by the library.
- A relay between the devices cannot rename a device or swap a key: both ids and display names are in the
  transcript, so altering one makes the confirmations fail.
- Anyone who learns the code before the run can pair. The code should live no longer than a person needs to type it.

## Supported versions

The latest tagged release. There are no long-lived release branches, so a fix ships in the next tag
rather than being backported.

## Reporting a vulnerability

Use GitHub's [private vulnerability reporting](https://github.com/Totative/go-codepair/security/advisories/new)
on this repository (Security → Report a vulnerability). It stays private until a fix ships.
The organisation's [security policy](https://github.com/Totative/.github/blob/main/SECURITY.md)
covers the rest, safe harbour included.

Please do not open a public issue for a suspected vulnerability first.

## What is in scope

- The code a user types, through `Normalize`, `NewJoiner` and `NewHost`: any bytes, any length, any encoding.
  `Normalize` must not panic or allocate without bound, and the same code however separated or capitalised must
  derive the same key. A code shorter than the `Config`'s length or outside its alphabet is refused.
- A peer's message, through `Host.Accept`, `Joiner.Finish` and `Host.Finish`: any bytes, empty included. Invalid
  encodings, the identity element and non-canonical identity encoding must be rejected without panicking, and no
  error path may return a key.
- The remote identifier and clock a caller passes to `Limiter.Charge` and `Refund`: any string, and a clock that
  moves backwards. None may panic or leave the counts negative.
- The `Config` a caller builds, through `Validate`: a zero or negative field, or a code under 32 bits, is refused
  rather than defaulted. The alphabet must be distinct printable ASCII that `Normalize` leaves alone.

## What is out of scope

- The transport and the lifetime of an open code are the caller's. This package never sees a wire, a clock, or a
  session, so a caller that does not charge the `Limiter` before each run, or honours a code forever, has weakened
  its own pairing.
- A caller must check `Pairing.PeerID` and `PeerName` against the device it meant to pair with before storing the
  key. The confirmation proves the peer sent those values, not that they are the right ones.
- The cipher suite is ristretto255 with SHA-512 in the initiator-responder setting, per draft-irtf-cfrg-cpace-21,
  which is an Internet-Draft and not yet an RFC.
- A caller may show the code grouped, in lower case, or read it aloud; `Normalize` accepts that. It leaves every
  other character alone, including characters outside the alphabet, which then fail.
- A device that completes pairing is trusted by whoever stored the key. This package proves knowledge of the code
  and binds the transcript; it does not decide which devices should pair, what a paired device may do, or when a
  stored key expires.
- The code itself is meant to be visible: the user reads it off one screen and types it into another. Anyone who can
  see that screen already has it.
- Ids and display names travel in clear in the pairing messages (draft-irtf-cfrg-cpace-21 section 10.1.1). The
  confirmation authenticates them; it does not hide them from a network observer.
- The session id is empty, so the draft's sid-uniqueness precondition and its quantum-annoying recommendation
  (sections 10.9 and 10.12) are not met. Each run already uses a fresh code, so generators differ without a sid,
  and the code is a short-lived, human-visible secret rather than a password reused across concurrent sessions.
