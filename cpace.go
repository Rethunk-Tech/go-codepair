package codepair

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gtank/ristretto255"
)

// The functions below are CPace (draft-irtf-cfrg-cpace-21) for the ristretto255 group and SHA-512, in the
// initiator-responder setting. They keep the draft's names so each can be read against its text.

const (
	cpaceDSI   = "CPaceRistretto255"
	hashBlock  = 128 // SHA-512 input block size, H.s_in_bytes
	elemSize   = 32
	scalarBits = 252
	tagSize    = sha512.Size
)

// ErrMessage reports a protocol message that is malformed or that CPace requires aborting on: a wrong length, an
// invalid or identity group element, or a non-canonical associated-data encoding.
var ErrMessage = errors.New("codepair: invalid pairing message")

// ErrConfirmation reports that the peer's key confirmation did not verify: the codes differ, or a message was
// altered in transit, so the peer did not derive the same key.
var ErrConfirmation = errors.New("codepair: key confirmation failed")

// lvCat is the draft's length-value concatenation, with LEB128 lengths, so no two field tuples encode to the same
// bytes.
func lvCat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = binary.AppendUvarint(out, uint64(len(p)))
		out = append(out, p...)
	}
	return out
}

// splitPair parses exactly two length-value fields and rejects trailing bytes and non-minimal lengths, so each field
// pair has one encoding.
func splitPair(b []byte) (first, second []byte, err error) {
	var fields [2][]byte
	for i := range fields {
		length, read := binary.Uvarint(b)
		rest := b[max(read, 0):]
		if read <= 0 || read != len(binary.AppendUvarint(nil, length)) || length > uint64(len(rest)) {
			return nil, nil, ErrMessage
		}
		fields[i], b = rest[:length], rest[length:]
	}
	if len(b) != 0 {
		return nil, nil, ErrMessage
	}
	return fields[0], fields[1], nil
}

// generatorString is the draft's generator_string. The zero padding fills the first hash block, so hashing a short
// code takes the same time whatever its length.
func generatorString(prs, ci, sid []byte) []byte {
	dsi := []byte(cpaceDSI)
	zpad := max(0, hashBlock-1-len(lvCat(prs))-len(lvCat(dsi)))
	return lvCat(dsi, prs, make([]byte, zpad), ci, sid)
}

// calculateGenerator derives the group generator from the password-related string, channel identifier and session
// id, so that a guess at the code yields a different generator.
func calculateGenerator(prs, ci, sid []byte) (*ristretto255.Element, error) {
	digest := sha512.Sum512(generatorString(prs, ci, sid))
	g, err := new(ristretto255.Element).SetUniformBytes(digest[:])
	if err != nil {
		return nil, fmt.Errorf("codepair: derive the generator: %w", err)
	}
	return g, nil
}

// scalarFromBytes reads the 32 little-endian bytes of a scalar after clearing the bits above the group size.
func scalarFromBytes(b []byte) (*ristretto255.Scalar, error) {
	masked := append([]byte(nil), b...)
	masked[elemSize-1] &= 1<<(scalarBits-8*(elemSize-1)) - 1
	s, err := new(ristretto255.Scalar).SetCanonicalBytes(masked)
	if err != nil {
		return nil, fmt.Errorf("codepair: read a scalar: %w", err)
	}
	return s, nil
}

// sampleScalar is the draft's recommended G.sample_scalar for ristretto255.
func sampleScalar() (*ristretto255.Scalar, error) {
	b := make([]byte, elemSize)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("codepair: draw a scalar: %w", err)
	}
	return scalarFromBytes(b)
}

// scalarMultVfy is G.scalar_mult_vfy plus the draft's abort rule: it fails on an invalid encoding and on an identity
// result, which a peer's identity or low-order share would force.
func scalarMultVfy(y *ristretto255.Scalar, point []byte) ([]byte, error) {
	p, err := new(ristretto255.Element).SetCanonicalBytes(point)
	if err != nil {
		return nil, ErrMessage
	}
	k := new(ristretto255.Element).ScalarMult(y, p)
	if k.Equal(ristretto255.NewIdentityElement()) == 1 {
		return nil, ErrMessage
	}
	return k.Bytes(), nil
}

// keyConfirmation derives ISK and the confirmation key from the shared point and the transcript. K itself never
// leaves this function.
func keyConfirmation(k, sid, ya, adA, yb, adB []byte) (isk, macKey []byte) {
	transcript := lvCat(ya, adA, yb, adB)
	digest := sha512.Sum512(append(lvCat([]byte(cpaceDSI+"_ISK"), sid, k), transcript...))
	mac := sha512.Sum512(append(append([]byte("CPaceMac"), sid...), digest[:]...))
	return digest[:], mac[:]
}

// confirmationTag authenticates the sender's own message under the confirmation key, as the draft's section 10.4
// describes.
func confirmationTag(macKey, y, ad []byte) []byte {
	mac := hmac.New(sha512.New, macKey)
	_, _ = mac.Write(lvCat(y, ad))
	return mac.Sum(nil)
}
