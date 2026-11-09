# HUMANS.md

Run and use `go-codepair`. Internals: [AGENTS.md](AGENTS.md).

## Quick start

```bash
go get github.com/Totative/go-codepair
```

The host shows a code, the joiner types it, and both end up holding the same long-term key for the other. The bytes
between them are the transport's business; this package only derives and checks them.

```go
package main

import (
 "crypto/ecdh"
 "crypto/rand"
 "fmt"
 "strings"

 "github.com/Totative/go-codepair"
)

// config is pinned by the caller; two peers agree on it before they pair.
var config = codepair.Config{
 Protocol:    "example-pair-v1",
 PeerKeyInfo: "example-peer-key",
 Iterations:  200_000,
 CodeLength:  8,
 Alphabet:    "ABCDEFGHJKMNPQRSTUVWXYZ23456789",
}

func main() {
 // The host shows a code; the joiner types it, perhaps in another case or with a stray separator.
 code, err := config.NewCode()
 if err != nil {
  panic(err)
 }
 fmt.Printf("code: %s-%s\n", code[:4], code[4:])
 typed := strings.ToLower(code[:4] + " " + code[4:])

 // Each side makes an X25519 key and sends its public half over the pairing link.
 joinerKey, err := ecdh.X25519().GenerateKey(rand.Reader)
 if err != nil {
  panic(err)
 }
 hostKey, err := ecdh.X25519().GenerateKey(rand.Reader)
 if err != nil {
  panic(err)
 }
 joinerPub, hostPub := joinerKey.PublicKey().Bytes(), hostKey.PublicKey().Bytes()

 // Both sides build the same transcript from the same fields in the same order.
 transcript := config.Transcript(joinerPub, hostPub, "joiner-id", "Laptop", "host-id", "Desktop")
 shared, err := joinerKey.ECDH(hostKey.PublicKey())
 if err != nil {
  panic(err)
 }

 // Same code, same transcript, same shared secret: the same two keys on both sides.
 authKey, peerKey, err := config.Keys(typed, shared, transcript)
 if err != nil {
  panic(err)
 }

 // The joiner proves first; the host answers only if that proof checks out.
 proof := codepair.Proof(authKey, "J", transcript, shared)
 if !codepair.Verify(codepair.Proof(authKey, "J", transcript, shared), proof) {
  panic("wrong code")
 }
 fmt.Printf("host answers %x\n", codepair.Proof(authKey, "H", transcript, shared))
 fmt.Printf("both sides store %d bytes for the other\n", len(peerKey))
}
```

A host serving guesses over a network also needs a `Limiter` (see the contract table): it is what keeps a short code
from being guessed online.

## Contracts

| Entry point | What it refuses, and what it guarantees |
| --- | --- |
| `Config.Validate` | Refuses an empty `Protocol` or `PeerKeyInfo`, `Iterations` or `CodeLength` below 1, and an `Alphabet` under two characters. It defaults nothing. |
| `Config.NewCode` | Refuses an invalid `Config`. Each character is drawn uniformly from `Alphabet`; a code is `CodeLength` bytes long and lives no longer than the caller keeps it. |
| `Normalize` | Never fails, never returns an error. Upper-cases and drops `-` and spaces only, so any other punctuation a user types is still a wrong code. |
| `Config.Keys` | Refuses an invalid `Config`. Returns 32-byte `authKey` and `peerKey`, or `nil, nil, err`; on error nothing is written. Both sides that pass the same normalised code, `shared` and `transcript` get identical keys. |
| `Config.Transcript` | Never fails. Every argument is length-delimited or fixed-width, so no two different inputs produce the same bytes by concatenation. |
| `Proof` | Never fails. Returns a 32-byte HMAC over role, transcript and shared secret; a different role yields a different proof, so one side's proof never passes as the other's. |
| `Verify` | Never fails. Compares in constant time; `nil` or short input is simply unequal. |
| `NewLimiter` | Accepts any bounds. A `maxFailures` or `burnFailures` below 1 makes the first charge lock or burn. |
| `Limiter.Locked` | Never fails. Reports a lockout only for the remote named; a lockout ends exactly `lockout` after the charge that set it. |
| `Limiter.Charge` | Never fails. Counts the guess before the caller checks it, so parallel guesses cannot outnumber the limit. Returns `burned` once the global count reaches `burnFailures`; the caller drops its code then. |
| `Limiter.Refund` | Never fails. Gives back one global guess and one per-remote failure. It never shortens a lockout, and the count never goes below zero. |

## Requirements

Go 1.27.3 or newer, plus `lefthook` and `gitleaks` on PATH if you want the git hooks.

```bash
lefthook install
```

That is per clone; git does not commit hooks. Pre-commit scans staged changes for secrets, and
pre-push runs `gate`.

## Verify

```bash
gate
```
