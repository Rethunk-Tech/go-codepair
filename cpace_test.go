package codepair

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gtank/ristretto255"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLengthValueVectors(t *testing.T) {
	t.Parallel()
	if got := hex.EncodeToString(lvCat([]byte("1234"), []byte("5"), nil, []byte("678"))); got != "043132333401350003363738" {
		t.Errorf("lv_cat = %s", got)
	}
	if got := hex.EncodeToString(lvCat(nil)); got != "00" {
		t.Errorf("prepend_len(empty) = %s", got)
	}
	long := make([]byte, 128)
	for i := range long {
		long[i] = byte(i)
	}
	if got := hex.EncodeToString(lvCat(long)[:4]); got != "80010001" {
		t.Errorf("prepend_len(128 bytes) starts %s", got)
	}
	if got := hex.EncodeToString(lvCat([]byte("123"), []byte("PartyA"), []byte("234"), []byte("PartyB"))); got != "03313233065061727479410332333406506172747942" {
		t.Errorf("transcript_ir = %s", got)
	}
}

// Every intermediate value of draft-irtf-cfrg-cpace-21, appendix B.3 (ristretto255, SHA-512).
func TestCFRGVectorsRistretto255(t *testing.T) {
	t.Parallel()
	prs := []byte("Password")
	ci := unhex(t, "0b415f696e69746961746f720b425f726573706f6e646572")
	sid := unhex(t, "7e4b4791d6a8ef019b936c79fb7f2c57")

	genString := generatorString(prs, ci, sid)
	wantString := unhex(t, `11435061636552697374726574746f3235350850617373776f726464`+strings.Repeat("00", 100)+
		`180b415f696e69746961746f720b425f726573706f6e646572107e4b4791d6a8ef019b936c79fb7f2c57`)
	if !bytes.Equal(genString, wantString) {
		t.Fatalf("generator_string = %x", genString)
	}
	digest := sha512.Sum512(genString)
	wantDigest := "da6d3ddc8802fca9058755ffd3ebde08a9c2c74945901a258482a288b6663af06bf645c93cd1c51512307199c80e84908916d983b34af77205f90851a657ee27"
	if hex.EncodeToString(digest[:]) != wantDigest {
		t.Fatalf("generator hash = %x", digest)
	}
	g, err := calculateGenerator(prs, ci, sid)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(g.Bytes()); got != "222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56" {
		t.Fatalf("g = %s", got)
	}

	ya, err := scalarFromBytes(unhex(t, "da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08"))
	if err != nil {
		t.Fatal(err)
	}
	yb, err := scalarFromBytes(unhex(t, "d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d"))
	if err != nil {
		t.Fatal(err)
	}
	Ya := new(ristretto255.Element).ScalarMult(ya, g).Bytes()
	Yb := new(ristretto255.Element).ScalarMult(yb, g).Bytes()
	if got := hex.EncodeToString(Ya); got != "d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b9157" {
		t.Errorf("Ya = %s", got)
	}
	if got := hex.EncodeToString(Yb); got != "3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f7258" {
		t.Errorf("Yb = %s", got)
	}

	const wantK = "80b69a8a76457ab6a4d7f887a4bf6b55a2f80ac19c333f917a05fc9887c8b40f"
	kA, err := scalarMultVfy(ya, Yb)
	if err != nil {
		t.Fatal(err)
	}
	kB, err := scalarMultVfy(yb, Ya)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(kA) != wantK || hex.EncodeToString(kB) != wantK {
		t.Errorf("K = %x, %x", kA, kB)
	}

	adA, adB := []byte("ADa"), []byte("ADb")
	wantTranscript := "20d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b915703414461203ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f725803414462"
	if got := hex.EncodeToString(lvCat(Ya, adA, Yb, adB)); got != wantTranscript {
		t.Errorf("transcript_ir = %s", got)
	}
	isk, _ := keyConfirmation(kA, sid, Ya, adA, Yb, adB)
	wantISK := "b69effbf61b51d56401c0f65601abe428de8206feaaf0e32198896dcae7b35cd2b38950a39dfd5d4a79164614c2984f7daa460b588c1e80c3fa2068af7900447"
	if hex.EncodeToString(isk) != wantISK {
		t.Errorf("ISK = %x", isk)
	}
}

func TestCFRGScalarMultVectors(t *testing.T) {
	t.Parallel()
	s, err := new(ristretto255.Scalar).SetCanonicalBytes(unhex(t, "7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := scalarMultVfy(s, unhex(t, "2c3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c"))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "7c13645fe790a468f62c39beb7388e541d8405d1ade69d1778c5fe3e7f6b600e" {
		t.Errorf("scalar_mult_vfy = %x", got)
	}
	for name, point := range map[string][]byte{
		"invalid encoding": unhex(t, "2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c"),
		"identity":         make([]byte, 32),
		"short":            make([]byte, 31),
		"empty":            nil,
	} {
		if _, err := scalarMultVfy(s, point); !errors.Is(err, ErrMessage) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestSplitLVIsCanonical(t *testing.T) {
	t.Parallel()
	if _, _, err := splitPair(lvCat([]byte("a"), []byte("b"))); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string][]byte{
		"trailing":    append(lvCat([]byte("a"), []byte("b")), 0),
		"one field":   lvCat([]byte("a")),
		"non-minimal": {0x81, 0x00, 'a', 0x00},
		"overlong":    {0x05, 'a', 0x00},
	} {
		if _, _, err := splitPair(in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// run drives a full exchange and returns both sides' results.
func run(t *testing.T, hostCode, joinCode string) (jp Pairing, jerr error, hp Pairing, herr error) {
	t.Helper()
	joiner, msgA, err := testConfig.NewJoiner(joinCode, "joiner-id", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	host, err := testConfig.NewHost(hostCode, "host-id", "Desktop")
	if err != nil {
		t.Fatal(err)
	}
	msgB, err := host.Accept(msgA)
	if err != nil {
		t.Fatal(err)
	}
	confirm, jp, jerr := joiner.Finish(msgB)
	if jerr != nil {
		return Pairing{}, jerr, Pairing{}, nil
	}
	hp, herr = host.Finish(confirm)
	return jp, nil, hp, herr
}

func TestFullRun(t *testing.T) {
	t.Parallel()
	jp, jerr, hp, herr := run(t, "ABCD2345", "abcd 2345")
	if jerr != nil || herr != nil {
		t.Fatal(jerr, herr)
	}
	if len(jp.PeerKey) != 32 || !bytes.Equal(jp.PeerKey, hp.PeerKey) {
		t.Fatalf("peer keys differ: %x, %x", jp.PeerKey, hp.PeerKey)
	}
	if jp.PeerID != "host-id" || jp.PeerName != "Desktop" || hp.PeerID != "joiner-id" || hp.PeerName != "Laptop" {
		t.Fatalf("identities: %+v %+v", jp, hp)
	}
	again, againErr, _, _ := run(t, "ABCD2345", "ABCD2345")
	if againErr != nil {
		t.Fatal(againErr)
	}
	if bytes.Equal(again.PeerKey, jp.PeerKey) {
		t.Fatal("two runs derived the same key")
	}
}

func TestPeerKeyInfoMismatchFailsConfirmation(t *testing.T) {
	t.Parallel()
	joinCfg := testConfig
	joinCfg.PeerKeyInfo = "other-peer-key"
	joiner, msgA, err := joinCfg.NewJoiner("ABCD2345", "joiner-id", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	host, err := testConfig.NewHost("ABCD2345", "host-id", "Desktop")
	if err != nil {
		t.Fatal(err)
	}
	msgB, err := host.Accept(msgA)
	if err != nil {
		t.Fatal(err)
	}
	confirm, jp, err := joiner.Finish(msgB)
	if !errors.Is(err, ErrConfirmation) {
		t.Fatalf("Finish err=%v pairing=%+v confirm=%d bytes, want ErrConfirmation", err, jp, len(confirm))
	}
	if jp.PeerKey != nil || jp.PeerID != "" || jp.PeerName != "" {
		t.Fatalf("Finish pairing %+v, want zero", jp)
	}
}

func TestTruncatedMessageDoesNotSpend(t *testing.T) {
	t.Parallel()
	joiner, msgA, err := testConfig.NewJoiner("ABCD2345", "joiner-id", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	host, err := testConfig.NewHost("ABCD2345", "host-id", "Desktop")
	if err != nil {
		t.Fatal(err)
	}
	msgB, err := host.Accept(msgA)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := joiner.Finish(msgB[:10]); !errors.Is(err, ErrMessage) {
		t.Fatalf("short Finish err=%v, want ErrMessage", err)
	}
	confirm, jp, err := joiner.Finish(msgB)
	if err != nil {
		t.Fatalf("Finish after short message: %v", err)
	}
	hp, err := host.Finish(confirm)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(jp.PeerKey, hp.PeerKey) {
		t.Fatalf("peer keys differ: %x, %x", jp.PeerKey, hp.PeerKey)
	}

	joiner2, msgA2, err := testConfig.NewJoiner("ABCD2345", "joiner-id", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	host2, err := testConfig.NewHost("ABCD2345", "host-id", "Desktop")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host2.Accept(make([]byte, 5)); !errors.Is(err, ErrMessage) {
		t.Fatalf("short Accept err=%v, want ErrMessage", err)
	}
	msgB2, err := host2.Accept(msgA2)
	if err != nil {
		t.Fatalf("Accept after short message: %v", err)
	}
	confirm2, jp2, err := joiner2.Finish(msgB2)
	if err != nil {
		t.Fatal(err)
	}
	hp2, err := host2.Finish(confirm2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(jp2.PeerKey, hp2.PeerKey) {
		t.Fatalf("peer keys differ after short Accept: %x, %x", jp2.PeerKey, hp2.PeerKey)
	}
}

func TestWrongCodeFailsOnBothSides(t *testing.T) {
	t.Parallel()
	// The joiner rejects the host's confirmation first, so the host never receives one to verify.
	_, jerr, hp, _ := run(t, "ABCD2345", "ABCD2346")
	if !errors.Is(jerr, ErrConfirmation) || hp.PeerKey != nil {
		t.Fatalf("joiner err = %v", jerr)
	}

	// A joiner that skips its own check and answers anyway is still rejected by the host.
	joiner, msgA, _ := testConfig.NewJoiner("ABCD2346", "j", "J")
	host, _ := testConfig.NewHost("ABCD2345", "h", "H")
	msgB, err := host.Accept(msgA)
	if err != nil {
		t.Fatal(err)
	}
	if _, p, err := joiner.Finish(msgB); err == nil || p.PeerKey != nil {
		t.Fatal("joiner accepted a host with another code")
	}
	forged := bytes.Repeat([]byte{1}, tagSize)
	if p, err := host.Finish(forged); !errors.Is(err, ErrConfirmation) || p.PeerKey != nil {
		t.Fatalf("host err = %v", err)
	}
}

// A rogue host that captured a joiner message and knows its own scalar learns nothing it can test other codes
// against: the joiner answers only after verifying a confirmation that needs the ISK, and the ISK needs the joiner's
// scalar or the host's, one of which the rogue lacks for every code but the true one.
func TestRogueHostGetsOneGuessPerRun(t *testing.T) {
	t.Parallel()
	const trueCode = "ABCD2345"
	_, msgA, err := testConfig.NewJoiner(trueCode, "joiner-id", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	ya := msgA[:elemSize]

	// Ya = ya*g(true), so the rogue's K = yb*Ya is the same whatever code it used to build its own share: the
	// capture is consistent with every guess and the rogue's side of the key never depends on the guess.
	yb, err := sampleScalar()
	if err != nil {
		t.Fatal(err)
	}
	var ks [][]byte
	for _, guess := range []string{"AAAAAAAA", "ABCD2346", trueCode} {
		g, err := calculateGenerator([]byte(guess), []byte(testConfig.Protocol), nil)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(new(ristretto255.Element).ScalarMult(yb, g).Bytes(), ya) {
			t.Fatal("a rogue share equalled the captured one")
		}
		k, err := scalarMultVfy(yb, ya)
		if err != nil {
			t.Fatal(err)
		}
		ks = append(ks, k)
	}
	for _, other := range ks[1:] {
		if !bytes.Equal(ks[0], other) {
			t.Fatal("the rogue's K depended on its code guess")
		}
	}

	// Answering a fresh joiner run succeeds only for the guess equal to the code at run time.
	for guess, wantOK := range map[string]bool{"AAAAAAAA": false, trueCode: true} {
		joiner, msgA, _ := testConfig.NewJoiner(trueCode, "joiner-id", "Laptop")
		rogue, _ := testConfig.NewHost(guess, "rogue", "Rogue")
		msgB, err := rogue.Accept(msgA)
		if err != nil {
			t.Fatal(err)
		}
		_, p, err := joiner.Finish(msgB)
		if (err == nil) != wantOK || (err != nil && p.PeerKey != nil) {
			t.Fatalf("guess %s: err = %v", guess, err)
		}
	}
}

func TestInvalidMessagesAreRejected(t *testing.T) {
	t.Parallel()
	identity := make([]byte, elemSize)
	notPoint := unhex(t, "2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c")
	ad := lvCat([]byte("id"), []byte("name"))

	for name, msg := range map[string][]byte{
		"short":          make([]byte, 5),
		"identity":       slices.Concat(identity, ad),
		"invalid point":  append(notPoint, ad...),
		"bad identity":   append(bytes.Clone(identity), 0xff),
		"trailing bytes": append(append([]byte(nil), notPoint...), append(ad, 1)...),
	} {
		host, _ := testConfig.NewHost("ABCD2345", "h", "H")
		if _, err := host.Accept(msg); !errors.Is(err, ErrMessage) {
			t.Errorf("host %s: err = %v", name, err)
		}
	}

	for name, msg := range map[string][]byte{
		"short":    make([]byte, 5),
		"identity": slices.Concat(identity, make([]byte, tagSize), ad),
	} {
		joiner, _, _ := testConfig.NewJoiner("ABCD2345", "j", "J")
		if _, _, err := joiner.Finish(msg); !errors.Is(err, ErrMessage) {
			t.Errorf("joiner %s: err = %v", name, err)
		}
	}
}

func TestTamperedIdentityFailsConfirmation(t *testing.T) {
	t.Parallel()
	joiner, msgA, _ := testConfig.NewJoiner("ABCD2345", "joiner-id", "Laptop")
	host, _ := testConfig.NewHost("ABCD2345", "host-id", "Desktop")
	msgB, err := host.Accept(msgA)
	if err != nil {
		t.Fatal(err)
	}
	msgB[len(msgB)-1] ^= 1 // a relay renames the host
	if _, _, err := joiner.Finish(msgB); !errors.Is(err, ErrConfirmation) {
		t.Fatalf("err = %v", err)
	}
}

func TestHandshakesAreSingleUse(t *testing.T) {
	t.Parallel()
	joiner, msgA, _ := testConfig.NewJoiner("ABCD2345", "j", "J")
	host, _ := testConfig.NewHost("ABCD2345", "h", "H")
	msgB, _ := host.Accept(msgA)
	if _, err := host.Accept(msgA); err == nil {
		t.Error("a host replied twice")
	}
	if _, err := host.Finish(nil); err == nil {
		t.Error("a host finished without a valid confirmation")
	}
	if _, err := host.Finish(nil); err == nil {
		t.Error("a spent host finished again")
	}
	if _, _, err := joiner.Finish(msgB); err != nil {
		t.Fatal(err)
	}
	if _, _, err := joiner.Finish(msgB); err == nil {
		t.Error("a joiner finished twice")
	}
}

func FuzzMessages(f *testing.F) {
	_, msgA, _ := testConfig.NewJoiner("ABCD2345", "j", "J")
	f.Add(msgA)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, msg []byte) {
		host, _ := testConfig.NewHost("ABCD2345", "h", "H")
		if reply, err := host.Accept(msg); err == nil && len(reply) < elemSize+tagSize {
			t.Fatalf("short reply %x", reply)
		}
		joiner, _, _ := testConfig.NewJoiner("ABCD2345", "j", "J")
		if confirm, p, err := joiner.Finish(msg); err == nil {
			t.Fatalf("joiner accepted fuzzed input: %x %v", confirm, p)
		}
	})
}
