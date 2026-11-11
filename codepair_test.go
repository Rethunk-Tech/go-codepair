package codepair

import (
	"strings"
	"testing"
	"time"
)

// testConfig is the shape a caller passes: eight characters from an alphabet without look-alikes.
var testConfig = Config{
	Protocol:    "example-pair-v1",
	PeerKeyInfo: "example-peer-key",
	CodeLength:  8,
	Alphabet:    "ABCDEFGHJKMNPQRSTUVWXYZ23456789",
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

func TestConfigValidation(t *testing.T) {
	t.Parallel()
	var zero Config
	if err := zero.Validate(); err == nil {
		t.Fatal("the zero config validated")
	}
	if _, err := zero.NewCode(); err == nil {
		t.Fatal("the zero config minted a code")
	}
	if _, _, err := zero.NewJoiner("code", "id", "name"); err == nil {
		t.Fatal("the zero config started a joiner")
	}
	if _, err := zero.NewHost("code", "id", "name"); err == nil {
		t.Fatal("the zero config started a host")
	}
	for name, alphabet := range map[string]string{
		"duplicate":  "ABCDEFGHJKMNPQRSTUVWXYZ2345678A",
		"non-ASCII":  "ABCDEFGHJKMNPQRSTUVWXYZ2345678\u00e9",
		"lower case": "ABCDEFGHJKMNPQRSTUVWXYZ2345678a",
		"dash":       "ABCDEFGHJKMNPQRSTUVWXYZ2345678-",
		"space":      "ABCDEFGHJKMNPQRSTUVWXYZ2345678 ",
	} {
		c := testConfig
		c.Alphabet = alphabet
		if c.Validate() == nil {
			t.Errorf("%s alphabet validated", name)
		}
	}
	short := testConfig
	short.CodeLength = 6 // 29.7 bits
	if short.Validate() == nil {
		t.Error("a code under MinCodeBits validated")
	}
	if err := testConfig.Validate(); err != nil {
		t.Errorf("the test config is refused: %v", err)
	}
	ok := Config{Protocol: "p", PeerKeyInfo: "i", CodeLength: 32, Alphabet: "AB"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{"Protocol", Config{PeerKeyInfo: "i", CodeLength: 32, Alphabet: "AB"}, "Protocol"},
		{"PeerKeyInfo", Config{Protocol: "p", CodeLength: 32, Alphabet: "AB"}, "PeerKeyInfo"},
		{"CodeLength", Config{Protocol: "p", PeerKeyInfo: "i", Alphabet: "AB"}, "CodeLength"},
		{"Alphabet", Config{Protocol: "p", PeerKeyInfo: "i", CodeLength: 32, Alphabet: "A"}, "Alphabet"},
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
	for range 3 {
		if locked, burned := limiter.Charge("192.0.2.9", now); locked || burned {
			t.Fatal("a guess within the limit was refused")
		}
	}
	if locked, _ := limiter.Charge("192.0.2.9", now); !locked {
		t.Fatal("the fourth guess was allowed")
	}
	if locked, _ := limiter.Charge("192.0.2.10", now); locked {
		t.Fatal("a lock on one remote covered another")
	}
	if locked, _ := limiter.Charge("192.0.2.9", now.Add(2*time.Minute)); locked {
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
	limiter.Charge("192.0.2.9", now)
	if locked, _ := limiter.Charge("192.0.2.9", now); locked {
		t.Fatal("the refunded guess still counted")
	}
	if locked, _ := limiter.Charge("192.0.2.9", now); !locked {
		t.Fatal("two unrefunded guesses did not lock")
	}
}

func TestLimiterBurnReportsTheGlobalCount(t *testing.T) {
	t.Parallel()
	now := time.Now()
	limiter := NewLimiter(50, 3, time.Minute)
	for i := range 4 {
		if _, burned := limiter.Charge("192.0.2."+string(rune('1'+i)), now); burned != (i == 3) {
			t.Fatalf("charge %d burned = %t", i+1, burned)
		}
	}
	limiter = NewLimiter(50, 3, time.Minute)
	limiter.Charge("192.0.2.1", now)
	limiter.Charge("192.0.2.2", now)
	limiter.Refund("192.0.2.1", now)
	if _, burned := limiter.Charge("192.0.2.3", now); burned {
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
	if locked, _ := exact.Charge("peer", now.Add(time.Minute)); !locked {
		t.Fatal("a quiet period of exactly the lockout reset the count")
	}
}
