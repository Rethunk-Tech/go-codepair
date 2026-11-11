package codepair

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestRevWeakCodeAccepted(t *testing.T) {
	t.Parallel()
	for _, code := range []string{"", "1", "----", "not in alphabet at all"} {
		if _, err := testConfig.NewHost(code, "h", "H"); !errors.Is(err, ErrCode) {
			t.Errorf("NewHost(%q) = %v, want ErrCode", code, err)
		}
		if _, _, err := testConfig.NewJoiner(code, "j", "J"); !errors.Is(err, ErrCode) {
			t.Errorf("NewJoiner(%q) = %v, want ErrCode", code, err)
		}
	}
}

func TestRevZeroHost(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() != nil {
			t.Fatal("zero-value Host.Accept panics")
		}
	}()
	var h Host
	if _, err := h.Accept(make([]byte, 40)); err == nil {
		t.Fatal("zero-value Host.Accept succeeded")
	}
}

func TestRevReflectionLatent(t *testing.T) {
	t.Parallel()
	h, err := testConfig.NewHost("ABCD2345", "host-id", "Desktop")
	if err != nil {
		t.Fatal(err)
	}
	msg := slices.Concat(h.s.ya, h.s.ad)
	if _, err := h.Accept(msg); !errors.Is(err, ErrMessage) {
		t.Fatalf("Host.Accept of its own share = %v, want ErrMessage", err)
	}

	j, _, err := testConfig.NewJoiner("ABCD2345", "joiner-id", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	hostMsg := slices.Concat(j.s.ya, make([]byte, tagSize), j.s.ad)
	if _, _, err := j.Finish(hostMsg); !errors.Is(err, ErrMessage) {
		t.Fatalf("Joiner.Finish of its own share = %v, want ErrMessage", err)
	}
}

func TestRevADBounds(t *testing.T) {
	t.Parallel()
	if _, err := testConfig.NewHost("ABCD2345", "", "H"); err == nil {
		t.Error("NewHost accepted an empty id")
	}
	long := strings.Repeat("a", 257)
	if _, err := testConfig.NewHost("ABCD2345", long, "H"); err == nil {
		t.Error("NewHost accepted a 257-byte id")
	}
	if _, err := testConfig.NewHost("ABCD2345", "h", long); err == nil {
		t.Error("NewHost accepted a 257-byte name")
	}
	if _, _, err := testConfig.NewJoiner("ABCD2345", "", "J"); err == nil {
		t.Error("NewJoiner accepted an empty id")
	}

	h, err := testConfig.NewHost("ABCD2345", "h", "H")
	if err != nil {
		t.Fatal(err)
	}
	g, err := calculateGenerator([]byte("ZZZZZZZZ"), []byte(testConfig.Protocol), nil)
	if err != nil {
		t.Fatal(err)
	}
	ya := g.Bytes()
	if _, err := h.Accept(slices.Concat(ya, lvCat(nil, []byte("n")))); !errors.Is(err, ErrMessage) {
		t.Errorf("Accept(empty id) = %v, want ErrMessage", err)
	}

	h, err = testConfig.NewHost("ABCD2345", "h", "H")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Accept(slices.Concat(ya, lvCat([]byte("h"), make([]byte, 257)))); !errors.Is(err, ErrMessage) {
		t.Errorf("Accept(257-byte name) = %v, want ErrMessage", err)
	}

	h, err = testConfig.NewHost("ABCD2345", "h", "H")
	if err != nil {
		t.Fatal(err)
	}
	big := make([]byte, 64<<20)
	if _, err := h.Accept(slices.Concat(ya, lvCat(nil, big))); !errors.Is(err, ErrMessage) {
		t.Fatalf("Accept(64 MiB name, empty id) = %v, want ErrMessage", err)
	}
}
