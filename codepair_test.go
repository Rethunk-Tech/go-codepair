package codepair

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// testConfig is the shape a caller passes: eight characters from an alphabet without look-alikes.
var testConfig = Config{
	Protocol:    "example-pair-v1",
	PeerKeyInfo: "example-peer-key",
	Iterations:  200_000,
	CodeLength:  8,
	Alphabet:    "ABCDEFGHJKMNPQRSTUVWXYZ23456789",
}

// fixedExchange is the same key material for every known-answer case.
func fixedExchange() (a, b, shared, transcript []byte) {
	shared = make([]byte, 32)
	a = make([]byte, 32)
	b = make([]byte, 32)
	for i := range shared {
		shared[i] = byte(i)
		a[i] = byte(0x40 + i)
		b[i] = byte(0x80 + i)
	}
	return a, b, shared, testConfig.Transcript(a, b, "joiner-id", "Laptop", "host-id", "Desktop")
}

// The vectors below were produced by the implementation this package was ported from, so a change to the transcript
// layout, the salt, the info string or the proof's field order breaks this test rather than two shipped devices.
func TestKnownAnswers(t *testing.T) {
	t.Parallel()
	_, _, shared, transcript := fixedExchange()
	if got := hex.EncodeToString(transcript); got != "6578616d706c652d706169722d763100"+
		"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"+
		"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"+
		"6a6f696e65722d6964004c6170746f7000686f73742d6964004465736b746f70" {
		t.Fatalf("transcript = %s", got)
	}

	authKey, peerKey, err := testConfig.Keys("abcd 2345", shared, transcript)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(authKey); got != "214c07ec095cbd6d0a62a293e6e764ed95101d95383579df9855ab3325cf5e59" {
		t.Errorf("authKey = %s", got)
	}
	if got := hex.EncodeToString(peerKey); got != "54954b1921e4eab17ad65699d21e280852eb7e8d59aa027ce21720920f3683f0" {
		t.Errorf("peerKey = %s", got)
	}
	for role, want := range map[string]string{
		"J": "cbf8e52d9f5bfb21960f2fbe647d733580ce252b0983e91b50a46f71f862bbde",
		"H": "265322773f263930df5293962e899092ef8d4dee8d5c9ca47f51590e610cbd1b",
	} {
		if got := hex.EncodeToString(Proof(authKey, role, transcript, shared)); got != want {
			t.Errorf("proof %s = %s", role, got)
		}
	}
}

func TestTranscriptBindsBothNames(t *testing.T) {
	t.Parallel()
	base := testConfig.Transcript([]byte("a"), []byte("b"), "j", "Joiner", "h", "Host")
	for _, other := range [][]byte{
		testConfig.Transcript([]byte("a"), []byte("b"), "j", "Eve", "h", "Host"),
		testConfig.Transcript([]byte("a"), []byte("b"), "j", "Joiner", "h", "Eve"),
		testConfig.Transcript([]byte("a"), []byte("b"), "j", "Joiner", "i", "Host"),
	} {
		if bytes.Equal(base, other) {
			t.Fatal("a transcript field is outside the transcript")
		}
	}
}

func TestVerifyRejectsATamperedProof(t *testing.T) {
	t.Parallel()
	want := []byte("proof")
	if !Verify(want, []byte("proof")) {
		t.Fatal("identical proofs did not verify")
	}
	for _, got := range [][]byte{[]byte("prooF"), []byte("proof "), nil} {
		if Verify(want, got) {
			t.Errorf("Verify accepted %q", got)
		}
	}
}

func TestNewCodeIsUniformOverTheAlphabet(t *testing.T) {
	t.Parallel()
	seen := map[rune]int{}
	for range 200 {
		code, err := testConfig.NewCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != testConfig.CodeLength {
			t.Fatalf("code %q is %d characters, want %d", code, len(code), testConfig.CodeLength)
		}
		for _, r := range code {
			if !strings.ContainsRune(testConfig.Alphabet, r) {
				t.Fatalf("code %q has %q, which is outside the alphabet", code, r)
			}
			seen[r]++
		}
	}
	if len(seen) < len(testConfig.Alphabet)/2 {
		t.Fatalf("200 codes used %d of %d characters", len(seen), len(testConfig.Alphabet))
	}
}

func TestZeroConfigIsRefused(t *testing.T) {
	t.Parallel()
	var zero Config
	if err := zero.Validate(); err == nil {
		t.Fatal("the zero config validated")
	}
	if _, err := zero.NewCode(); err == nil {
		t.Fatal("the zero config minted a code")
	}
	if _, _, err := zero.Keys("code", make([]byte, 32), nil); err == nil {
		t.Fatal("the zero config derived keys")
	}
	ok := Config{Protocol: "p", PeerKeyInfo: "i", Iterations: 1, CodeLength: 1, Alphabet: "ab"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{"Protocol", Config{PeerKeyInfo: "i", Iterations: 1, CodeLength: 1, Alphabet: "ab"}, "Protocol"},
		{"PeerKeyInfo", Config{Protocol: "p", Iterations: 1, CodeLength: 1, Alphabet: "ab"}, "PeerKeyInfo"},
		{"Iterations", Config{Protocol: "p", PeerKeyInfo: "i", CodeLength: 1, Alphabet: "ab"}, "Iterations"},
		{"CodeLength", Config{Protocol: "p", PeerKeyInfo: "i", Iterations: 1, Alphabet: "ab"}, "CodeLength"},
		{"Alphabet", Config{Protocol: "p", PeerKeyInfo: "i", Iterations: 1, CodeLength: 1, Alphabet: "a"}, "Alphabet"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want %s", err, tc.want)
			}
		})
	}
}

func FuzzNormalizeIsIdempotent(f *testing.F) {
	f.Add("abcd-2345")
	f.Add("ABCD 2345")
	f.Add("")
	f.Fuzz(func(t *testing.T, code string) {
		once := Normalize(code)
		if twice := Normalize(once); twice != once {
			t.Fatalf("Normalize(%q) = %q, then %q", code, once, twice)
		}
	})
}

func TestLimiterLocksOutOneRemote(t *testing.T) {
	t.Parallel()
	now := time.Now()
	limiter := NewLimiter(3, 10, time.Minute)
	for i := range 3 {
		if limiter.Locked("192.0.2.9", now) {
			t.Fatalf("locked after %d guesses", i)
		}
		if limiter.Charge("192.0.2.9", now) {
			t.Fatal("an unburned limiter reported a burn")
		}
	}
	if !limiter.Locked("192.0.2.9", now) {
		t.Fatal("the fourth guess was allowed")
	}
	if limiter.Locked("192.0.2.10", now) {
		t.Fatal("a lock on one remote covered another")
	}
	if limiter.Locked("192.0.2.9", now.Add(2*time.Minute)) {
		t.Fatal("the lockout outlived its duration")
	}
}

// A remote that fails a few times and then succeeds gets its guess back, so one typo does not spend the budget.
func TestLimiterRefundReturnsAGuess(t *testing.T) {
	t.Parallel()
	now := time.Now()
	limiter := NewLimiter(2, 10, time.Minute)
	limiter.Charge("192.0.2.9", now)
	limiter.Refund("192.0.2.9", now)
	limiter.Refund("192.0.2.9", now)
	if limiter.Charge("192.0.2.9", now) {
		t.Fatal("a refunded limiter reported a burn")
	}
	if limiter.Locked("192.0.2.9", now) {
		t.Fatal("the refund did not give the guess back")
	}
	limiter.Charge("192.0.2.9", now)
	if !limiter.Locked("192.0.2.9", now) {
		t.Fatal("the refunded guess still counted")
	}
}

func TestLimiterBurnReportsTheGlobalCount(t *testing.T) {
	t.Parallel()
	now := time.Now()
	limiter := NewLimiter(50, 3, time.Minute)
	for i := range 3 {
		if burned := limiter.Charge("192.0.2."+string(rune('1'+i)), now); burned != (i == 2) {
			t.Fatalf("charge %d burned = %t", i+1, burned)
		}
	}
	limiter = NewLimiter(50, 3, time.Minute)
	limiter.Charge("192.0.2.1", now)
	limiter.Charge("192.0.2.2", now)
	limiter.Refund("192.0.2.1", now)
	if limiter.Charge("192.0.2.3", now) {
		t.Fatal("refund did not give the global guess back")
	}
}

// A lock nobody has touched for a whole lockout says nothing about a computer that comes back tomorrow, so the next
// charge drops it instead of keeping one map entry for every address that ever guessed.
func TestLimiterForgetsRemotesLongQuiet(t *testing.T) {
	t.Parallel()
	now := time.Now()
	limiter := NewLimiter(5, 15, time.Minute)
	limiter.Charge("old", now.Add(-2*time.Minute))
	limiter.Charge("new", now)
	limiter.mu.Lock()
	_, kept := limiter.locks["old"]
	size := len(limiter.locks)
	limiter.mu.Unlock()
	if kept || size != 1 {
		t.Errorf("locks = %d entries, old kept = %t", size, kept)
	}
	exact := NewLimiter(2, 10, time.Minute)
	exact.Charge("peer", now)
	exact.Charge("peer", now.Add(time.Minute))
	if !exact.Locked("peer", now.Add(time.Minute)) {
		t.Fatal("a quiet period of exactly the lockout reset the count")
	}
}
