# HUMANS.md

Run and use `go-codepair`. Internals: [AGENTS.md](AGENTS.md).

## Quick start

```bash
go get github.com/Totative/go-codepair
```

The host shows a code, the joiner types it, and both end up holding the same long-term key for the other. The bytes
between them are the transport's business; this package only builds and checks them.

```go
package main

import (
	"fmt"

	"github.com/Totative/go-codepair"
)

// config is pinned by the caller; two peers agree on it before they pair.
var config = codepair.Config{
	Protocol:    "example-pair-v1",
	PeerKeyInfo: "example-peer-key",
	CodeLength:  8,
	Alphabet:    "ABCDEFGHJKMNPQRSTUVWXYZ23456789",
}

func main() {
	code, err := config.NewCode()
	if err != nil {
		panic(err)
	}
	host, err := config.NewHost(code, "host-id", "Desktop")
	if err != nil {
		panic(err)
	}
	// The joiner may type the code in another case or with a stray separator.
	joiner, toHost, err := config.NewJoiner(code[:4]+" "+code[4:], "joiner-id", "Laptop")
	if err != nil {
		panic(err)
	}

	// The host charges its Limiter here, then replies.
	toJoiner, err := host.Accept(toHost)
	if err != nil {
		panic(err)
	}
	confirm, joined, err := joiner.Finish(toJoiner)
	if err != nil {
		panic(err) // wrong code, or the host's message was altered
	}
	hosted, err := host.Finish(confirm)
	if err != nil {
		panic(err)
	}
	fmt.Printf("joiner stores %d bytes for %s; host stores %d bytes for %s\n",
		len(joined.PeerKey), joined.PeerName, len(hosted.PeerKey), hosted.PeerName)
}
```

A host must charge a `Limiter` once per run, before `Host.Accept`, and refund it when `Host.Finish` succeeds: that
is what keeps a short code from being guessed online.

## Contracts

| Entry point | What it refuses, and what it guarantees |
| --- | --- |
| `Config.Validate` | Refuses an empty `Protocol` or `PeerKeyInfo`, `CodeLength` below 1, an alphabet with fewer than two characters, repeated or non-ASCII or non-printable characters, lower case, `-` or space, and a code under `MinCodeBits` (32). It defaults nothing. |
| `Config.NewCode` | Refuses an invalid `Config`. Each character is drawn uniformly from `Alphabet`; a code is `CodeLength` bytes long and lives no longer than the caller keeps it. |
| `Normalize` | Never fails. Upper-cases and drops `-` and spaces only, so any other punctuation a user types is still a wrong code. |
| `Config.NewJoiner` | Refuses an invalid `Config`. Returns the joiner and the one message for the host. A `Joiner` runs once. |
| `Joiner.Finish` | Takes the host's message. Returns the confirmation to send and the `Pairing`, or `ErrMessage` / `ErrConfirmation` with nothing else. |
| `Config.NewHost` | Refuses an invalid `Config`. A `Host` serves one run. |
| `Host.Accept` | Takes the joiner's message and returns the reply. Rejects malformed, invalid-point and identity messages with `ErrMessage`. The caller charges the `Limiter` first. |
| `Host.Finish` | Takes the joiner's confirmation. Returns the `Pairing` only if it verifies in constant time; otherwise `ErrConfirmation` and nothing else. |
| `Pairing` | `PeerKey` is 32 bytes, identical on both sides. `PeerID` and `PeerName` come from the peer's message; the caller checks them before storing the key. |
| `NewLimiter` | Accepts any bounds. A `maxFailures` or `burnFailures` below 1 makes the first charge lock or burn. |
| `Limiter.Charge` | Never fails. Returns `locked` while the remote is inside a lockout and `burned` once the global budget is spent; neither counts the guess, and the caller refuses the run. Otherwise counts it. Checking and counting are one atomic step. |
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
