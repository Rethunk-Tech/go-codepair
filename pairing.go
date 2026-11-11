package codepair

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/gtank/ristretto255"
)

// Pairing is what a completed, confirmed run yields. PeerID and PeerName arrive in the peer's message and are
// authenticated by the confirmation, but this package cannot know which peer the caller meant to pair with: the
// caller must check them before it stores PeerKey.
type Pairing struct {
	PeerKey  []byte
	PeerID   string
	PeerName string
}

var errUsed = errors.New("codepair: this handshake has already been used")

const (
	maxADField        = 256
	maxPairingMessage = 1024
)

func checkPeerAD(id, name []byte) error {
	if len(id) == 0 || len(id) > maxADField || len(name) > maxADField {
		return ErrMessage
	}
	return nil
}

// session holds what both roles start from. The channel identifier is the protocol label, so a peer running another
// protocol derives another generator and fails confirmation.
type session struct {
	cfg Config
	g   *ristretto255.Element
	y   *ristretto255.Scalar
	ya  []byte
	ad  []byte
}

func (c Config) newSession(code, id, name string) (*session, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	code = Normalize(code)
	if len(code) != c.CodeLength {
		return nil, fmt.Errorf("codepair: code is %d characters, want %d: %w", len(code), c.CodeLength, ErrCode)
	}
	for i := 0; i < len(code); i++ {
		if !strings.ContainsRune(c.Alphabet, rune(code[i])) {
			return nil, fmt.Errorf("codepair: code character %q is outside the alphabet: %w", code[i], ErrCode)
		}
	}
	switch {
	case id == "":
		return nil, errors.New("codepair: id is empty")
	case len(id) > maxADField:
		return nil, fmt.Errorf("codepair: id is %d bytes, want at most %d", len(id), maxADField)
	case len(name) > maxADField:
		return nil, fmt.Errorf("codepair: name is %d bytes, want at most %d", len(name), maxADField)
	}
	g, err := calculateGenerator([]byte(code), []byte(c.Protocol), nil)
	if err != nil {
		return nil, err
	}
	y, err := sampleScalar()
	if err != nil {
		return nil, err
	}
	return &session{
		cfg: c,
		g:   g,
		y:   y,
		ya:  new(ristretto255.Element).ScalarMult(y, g).Bytes(),
		ad:  lvCat([]byte(id), []byte(name)),
	}, nil
}

// pairing derives the stored key from ISK and reads the peer's identity from its associated data.
func (s *session) pairing(isk, peerAD []byte) (Pairing, error) {
	id, name, err := splitPair(peerAD)
	if err != nil {
		return Pairing{}, err
	}
	if err := checkPeerAD(id, name); err != nil {
		return Pairing{}, err
	}
	key, err := hkdf.Key(sha512.New, isk, nil, s.cfg.PeerKeyInfo, 32)
	if err != nil {
		return Pairing{}, fmt.Errorf("codepair: derive the peer key: %w", err)
	}
	return Pairing{PeerKey: key, PeerID: string(id), PeerName: string(name)}, nil
}

// Joiner is the side that types the code. It speaks first. A Joiner is not safe for concurrent use and serves one
// pairing attempt: a failed run needs a new one with a fresh secret.
type Joiner struct{ s *session }

// NewJoiner starts a run with the code the user typed and this device's id and display name. The returned message
// goes to the host.
func (c Config) NewJoiner(code, id, name string) (*Joiner, []byte, error) {
	s, err := c.newSession(code, id, name)
	if err != nil {
		return nil, nil, err
	}
	return &Joiner{s: s}, slices.Concat(s.ya, s.ad), nil
}

// Finish takes the host's message. It succeeds only when the host's confirmation verifies, which a host that does
// not know the code cannot produce, and then returns the confirmation to send back and the pairing. On any error
// the Joiner is spent and nothing else is returned.
func (j *Joiner) Finish(hostMsg []byte) (confirm []byte, p Pairing, err error) {
	s := j.s
	if s == nil {
		return nil, Pairing{}, errUsed
	}
	j.s = nil
	if len(hostMsg) > maxPairingMessage || len(hostMsg) < elemSize+tagSize {
		return nil, Pairing{}, ErrMessage
	}
	yb, tb, adB := hostMsg[:elemSize], hostMsg[elemSize:elemSize+tagSize], hostMsg[elemSize+tagSize:]
	if hmac.Equal(yb, s.ya) {
		return nil, Pairing{}, ErrMessage
	}
	k, err := scalarMultVfy(s.y, yb)
	if err != nil {
		return nil, Pairing{}, err
	}
	isk, macKey := keyConfirmation(k, nil, s.ya, s.ad, yb, adB)
	if !hmac.Equal(tb, confirmationTag(macKey, yb, adB)) {
		return nil, Pairing{}, ErrConfirmation
	}
	p, err = s.pairing(isk, adB)
	if err != nil {
		return nil, Pairing{}, err
	}
	return confirmationTag(macKey, s.ya, s.ad), p, nil
}

// Host is the side that shows the code. A Host is not safe for concurrent use and serves one pairing attempt. A
// caller charges its Limiter for the remote before Accept, because the reply lets whoever sent the joiner message
// test one guess.
type Host struct {
	s        *session
	macKey   []byte
	isk      []byte
	peerY    []byte
	peerAD   []byte
	accepted bool
}

// NewHost prepares a run with the code this device showed and its own id and display name.
func (c Config) NewHost(code, id, name string) (*Host, error) {
	s, err := c.newSession(code, id, name)
	if err != nil {
		return nil, err
	}
	return &Host{s: s}, nil
}

// Accept takes the joiner's message and returns the reply, which carries the host's confirmation. The caller must
// charge the Limiter for the remote before calling Accept, because the reply is one guess at the code. The run is
// unconfirmed until Finish verifies the joiner's answer.
func (h *Host) Accept(joinerMsg []byte) ([]byte, error) {
	if h.s == nil || h.accepted {
		return nil, errUsed
	}
	h.accepted = true
	if len(joinerMsg) > maxPairingMessage || len(joinerMsg) < elemSize {
		return nil, ErrMessage
	}
	s := h.s
	ya, adA := slices.Clone(joinerMsg[:elemSize]), slices.Clone(joinerMsg[elemSize:])
	if hmac.Equal(ya, s.ya) {
		return nil, ErrMessage
	}
	k, err := scalarMultVfy(s.y, ya)
	if err != nil {
		return nil, err
	}
	// Splitting here rejects a malformed identity before the host spends a confirmation on it.
	id, name, err := splitPair(adA)
	if err != nil {
		return nil, err
	}
	if err := checkPeerAD(id, name); err != nil {
		return nil, err
	}
	h.isk, h.macKey = keyConfirmation(k, nil, ya, adA, s.ya, s.ad)
	h.peerY, h.peerAD = ya, adA
	return slices.Concat(s.ya, confirmationTag(h.macKey, s.ya, s.ad), s.ad), nil
}

// Finish takes the joiner's confirmation. Only a joiner that derived the same key can produce it, so on success
// the host may store the returned pairing; on any error the Host is spent and nothing else is returned.
func (h *Host) Finish(confirm []byte) (Pairing, error) {
	if h.isk == nil {
		return Pairing{}, errUsed
	}
	isk, macKey, y, ad := h.isk, h.macKey, h.peerY, h.peerAD
	h.isk, h.macKey = nil, nil
	if !hmac.Equal(confirm, confirmationTag(macKey, y, ad)) {
		return Pairing{}, ErrConfirmation
	}
	return h.s.pairing(isk, ad)
}
