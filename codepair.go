package codepair

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
)

// Config names the pairing protocol this caller runs. The zero value is not usable: Validate refuses a config that
// leaves any field out, because an empty Protocol or PeerKeyInfo would derive keys under a shared, guessable label
// and a zero Iterations would make the code's stretch free.
type Config struct {
	Protocol    string
	PeerKeyInfo string
	Iterations  int
	CodeLength  int
	Alphabet    string
}

// Validate reports whether c can mint codes and derive keys. It refuses a zero field rather than defaulting one,
// since a default would name a product's protocol inside a library that has none.
func (c Config) Validate() error {
	switch {
	case c.Protocol == "":
		return errors.New("codepair: Protocol is empty")
	case c.PeerKeyInfo == "":
		return errors.New("codepair: PeerKeyInfo is empty")
	case c.Iterations < 1:
		return errors.New("codepair: Iterations must be at least 1")
	case c.CodeLength < 1:
		return errors.New("codepair: CodeLength must be at least 1")
	case len(c.Alphabet) < 2:
		return errors.New("codepair: Alphabet needs at least two characters")
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

// Normalize folds a typed code into the form Keys hashes: upper case, without the dashes and spaces a caller puts
// between groups. It never fails, so a caller can pass whatever the user entered.
func Normalize(code string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(code))
}

// Keys derives the two secrets of one pairing from the typed code and the X25519 shared secret. authKey is the key
// Proof signs with, stretched from the low-entropy code so that one guess costs c.Iterations of PBKDF2; peerKey is
// the long-term key HKDF derives from shared alone, so what a caller stores never depends on the code.
func (c Config) Keys(code string, shared, transcript []byte) (authKey, peerKey []byte, err error) {
	if err := c.Validate(); err != nil {
		return nil, nil, err
	}
	authKey, err = pbkdf2.Key(sha256.New, Normalize(code), []byte(c.Protocol), c.Iterations, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("codepair: stretch the code: %w", err)
	}
	digest := sha256.Sum256(transcript)
	peerKey, err = hkdf.Key(sha256.New, shared, digest[:], c.PeerKeyInfo, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("codepair: derive the peer key: %w", err)
	}
	return authKey, peerKey, nil
}

// Transcript builds the bytes both sides prove over: the protocol, both public keys, then both ids and display
// names. Because the names are in it, a relay that swaps the name a device is stored under fails the proofs.
func (c Config) Transcript(a, b []byte, joinerID, joinerName, hostID, hostName string) []byte {
	return slices.Concat([]byte(c.Protocol), []byte{0}, a, b, []byte(joinerID), []byte{0}, []byte(joinerName), []byte{0}, []byte(hostID), []byte{0}, []byte(hostName))
}

// Proof signs the transcript and the shared secret under authKey with the role the signer plays, so each side sends a
// different proof and a captured one cannot be replayed as the other.
func Proof(authKey []byte, role string, transcript, shared []byte) []byte {
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write([]byte(role))
	_, _ = mac.Write(transcript)
	_, _ = mac.Write(shared)
	return mac.Sum(nil)
}

// Verify reports whether two proofs match, in time that does not depend on where they first differ.
func Verify(want, got []byte) bool {
	return hmac.Equal(want, got)
}
