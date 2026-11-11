package codepair

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

// MinCodeBits is the least entropy Validate accepts for a code. The code is the only secret and an active attacker
// gets one guess per run, so the floor keeps a run's success chance, and the Limiter budget times it, small.
const MinCodeBits = 32

// ErrCode reports a pairing code that is not exactly Config.CodeLength characters from Config.Alphabet after
// Normalize. Running the handshake on a weaker secret would give an attacker a better guess than Validate allowed.
var ErrCode = errors.New("codepair: invalid pairing code")

// Config names the pairing protocol this caller runs. The zero value is not usable: Validate refuses a config that
// leaves any field out, because an empty Protocol or PeerKeyInfo would derive keys under a shared, guessable label.
type Config struct {
	Protocol    string
	PeerKeyInfo string
	CodeLength  int
	Alphabet    string
}

// Validate reports whether c can mint codes and run a pairing. It refuses a zero field rather than defaulting one,
// since a default would name a product's protocol inside a library that has none. The alphabet must be distinct
// printable ASCII that Normalize leaves alone, so a typed code maps to exactly one string, and the code must carry
// at least MinCodeBits of entropy.
func (c Config) Validate() error {
	switch {
	case c.Protocol == "":
		return errors.New("codepair: Protocol is empty")
	case c.PeerKeyInfo == "":
		return errors.New("codepair: PeerKeyInfo is empty")
	case c.CodeLength < 1:
		return errors.New("codepair: CodeLength must be at least 1")
	}
	seen := map[rune]bool{}
	for _, r := range c.Alphabet {
		switch {
		case r <= ' ' || r > '~':
			return fmt.Errorf("codepair: Alphabet character %q is not printable ASCII", r)
		case r == '-' || (r >= 'a' && r <= 'z'):
			return fmt.Errorf("codepair: Alphabet character %q is altered by Normalize", r)
		case seen[r]:
			return fmt.Errorf("codepair: Alphabet repeats %q", r)
		}
		seen[r] = true
	}
	if len(seen) < 2 {
		return errors.New("codepair: Alphabet needs at least two characters")
	}
	if bits := float64(c.CodeLength) * math.Log2(float64(len(seen))); bits < MinCodeBits {
		return fmt.Errorf("codepair: a code carries %.1f bits, want at least %d", bits, MinCodeBits)
	}
	return nil
}

// NewCode returns a code of c.CodeLength characters drawn uniformly from c.Alphabet. It is the secret the user types,
// so a caller may show it in any grouping it likes: Normalize drops the separators again.
func (c Config) NewCode() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	limit := big.NewInt(int64(len(c.Alphabet)))
	out := make([]byte, c.CodeLength)
	for i := range out {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", fmt.Errorf("codepair: draw a code character: %w", err)
		}
		out[i] = c.Alphabet[n.Int64()]
	}
	return string(out), nil
}

// Normalize folds a typed code into the form the handshake uses: upper case, without the dashes and spaces a caller
// puts between groups. It never fails, so a caller can pass whatever the user entered.
func Normalize(code string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(code))
}
