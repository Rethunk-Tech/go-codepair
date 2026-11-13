package codepair_test

import (
	"fmt"
	"time"

	"github.com/Totative/go-codepair"
)

// config is pinned by the caller; two peers agree on it before they pair.
var config = codepair.Config{
	Protocol:    "example-pair-v1",
	PeerKeyInfo: "example-peer-key",
	CodeLength:  8,
	Alphabet:    "ABCDEFGHJKMNPQRSTUVWXYZ23456789",
}

func Example() {
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
	limiter, err := codepair.NewLimiter(3, 100, time.Minute)
	if err != nil {
		panic(err)
	}
	now := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)

	toJoiner, err := host.Accept(toHost, limiter, "192.0.2.1", now)
	if err != nil {
		panic(err)
	}
	confirm, joined, err := joiner.Finish(toJoiner)
	if err != nil {
		panic(err)
	}
	hosted, err := host.Finish(confirm)
	if err != nil {
		panic(err)
	}
	fmt.Printf("joiner stores %d bytes for %s; host stores %d bytes for %s\n",
		len(joined.PeerKey), joined.PeerName, len(hosted.PeerKey), hosted.PeerName)
	// Output:
	// joiner stores 32 bytes for Desktop; host stores 32 bytes for Laptop
}

func ExampleConfig_Validate() {
	fmt.Println(config.Validate())
	// Output:
	// <nil>
}

func ExampleConfig_NewCode() {
	code, err := config.NewCode()
	if err != nil {
		panic(err)
	}
	_ = code
	// Drawn from crypto/rand; the code differs every run, so no // Output:.
}

func ExampleNormalize() {
	fmt.Println(codepair.Normalize("ab-cd ef"))
	// Output:
	// ABCDEF
}

func ExampleConfig_NewJoiner() {
	code, err := config.NewCode()
	if err != nil {
		panic(err)
	}
	joiner, toHost, err := config.NewJoiner(code, "joiner-id", "Laptop")
	fmt.Println(err == nil, joiner != nil, len(toHost) > 0)
	// Output:
	// true true true
}

func ExampleConfig_NewHost() {
	code, err := config.NewCode()
	if err != nil {
		panic(err)
	}
	host, err := config.NewHost(code, "host-id", "Desktop")
	fmt.Println(err == nil, host != nil)
	// Output:
	// true true
}

func ExampleJoiner_Finish() {
	code, err := config.NewCode()
	if err != nil {
		panic(err)
	}
	host, err := config.NewHost(code, "host-id", "Desktop")
	if err != nil {
		panic(err)
	}
	joiner, toHost, err := config.NewJoiner(code, "joiner-id", "Laptop")
	if err != nil {
		panic(err)
	}
	limiter, err := codepair.NewLimiter(3, 100, time.Minute)
	if err != nil {
		panic(err)
	}
	now := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)
	toJoiner, err := host.Accept(toHost, limiter, "192.0.2.1", now)
	if err != nil {
		panic(err)
	}
	confirm, joined, err := joiner.Finish(toJoiner)
	fmt.Println(err == nil, len(confirm) > 0, len(joined.PeerKey), joined.PeerName)
	// Output:
	// true true 32 Desktop
}

func ExampleHost_Accept() {
	code, err := config.NewCode()
	if err != nil {
		panic(err)
	}
	host, err := config.NewHost(code, "host-id", "Desktop")
	if err != nil {
		panic(err)
	}
	_, toHost, err := config.NewJoiner(code, "joiner-id", "Laptop")
	if err != nil {
		panic(err)
	}
	limiter, err := codepair.NewLimiter(3, 100, time.Minute)
	if err != nil {
		panic(err)
	}
	now := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)
	toJoiner, err := host.Accept(toHost, limiter, "192.0.2.1", now)
	fmt.Println(err == nil, len(toJoiner) > 0)
	// Output:
	// true true
}

func ExampleHost_Finish() {
	code, err := config.NewCode()
	if err != nil {
		panic(err)
	}
	host, err := config.NewHost(code, "host-id", "Desktop")
	if err != nil {
		panic(err)
	}
	joiner, toHost, err := config.NewJoiner(code, "joiner-id", "Laptop")
	if err != nil {
		panic(err)
	}
	limiter, err := codepair.NewLimiter(3, 100, time.Minute)
	if err != nil {
		panic(err)
	}
	now := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)
	toJoiner, err := host.Accept(toHost, limiter, "192.0.2.1", now)
	if err != nil {
		panic(err)
	}
	confirm, _, err := joiner.Finish(toJoiner)
	if err != nil {
		panic(err)
	}
	hosted, err := host.Finish(confirm)
	fmt.Println(err == nil, len(hosted.PeerKey), hosted.PeerName)
	// Output:
	// true 32 Laptop
}

func ExampleNewLimiter() {
	limiter, err := codepair.NewLimiter(3, 100, time.Minute)
	fmt.Println(err == nil, limiter != nil)
	// Output:
	// true true
}

func ExampleLimiter_Charge() {
	limiter, err := codepair.NewLimiter(3, 100, time.Minute)
	if err != nil {
		panic(err)
	}
	now := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)
	locked, burned := limiter.Charge("192.0.2.1", now)
	fmt.Println(locked, burned)
	// Output:
	// false false
}

func ExampleLimiter_Refund() {
	limiter, err := codepair.NewLimiter(3, 100, time.Minute)
	if err != nil {
		panic(err)
	}
	now := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)
	limiter.Charge("192.0.2.1", now)
	limiter.Refund("192.0.2.1", now)
	locked, burned := limiter.Charge("192.0.2.1", now)
	fmt.Println(locked, burned)
	// Output:
	// false false
}
