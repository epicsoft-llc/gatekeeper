package seal

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

var secret = []byte(strings.Repeat("k", 40))

func TestRoundTrip(t *testing.T) {
	box := New(secret, "session")
	sealed := box.Seal([]byte("hello"), []byte("a.example.com"))
	plain, err := box.Open(sealed, []byte("a.example.com"))
	if err != nil || string(plain) != "hello" {
		t.Fatalf("got %q, %v", plain, err)
	}
	if again := box.Seal([]byte("hello"), []byte("a.example.com")); again == sealed {
		t.Error("two seals of the same value are equal - the nonce is not random")
	}
}

func TestOpenRefuses(t *testing.T) {
	box := New(secret, "session")
	sealed := box.Seal([]byte("hello"), []byte("a.example.com"))
	raw, _ := base64.RawURLEncoding.DecodeString(sealed)
	flipped := bytes.Clone(raw)
	flipped[len(flipped)-1] ^= 1

	cases := map[string]struct {
		box    *Box
		sealed string
		aad    string
	}{
		"other host":    {box, sealed, "b.example.com"},
		"other purpose": {New(secret, "pending"), sealed, "a.example.com"},
		"other secret":  {New([]byte(strings.Repeat("x", 40)), "session"), sealed, "a.example.com"},
		"tampered":      {box, base64.RawURLEncoding.EncodeToString(flipped), "a.example.com"},
		"truncated":     {box, sealed[:20], "a.example.com"},
		"not base64":    {box, "*" + sealed, "a.example.com"},
		"empty":         {box, "", "a.example.com"},
	}
	for name, c := range cases {
		if plain, err := c.box.Open(c.sealed, []byte(c.aad)); err == nil {
			t.Errorf("%s: opened as %q", name, plain)
		}
	}
}

func TestKeysDifferByPurpose(t *testing.T) {
	if bytes.Equal(Key(secret, "a"), Key(secret, "b")) {
		t.Error("two purposes share a key")
	}
	if len(Key(secret, "a")) != 32 {
		t.Error("key is not 32 bytes")
	}
}

func FuzzOpen(f *testing.F) {
	box := New(secret, "session")
	f.Add(box.Seal([]byte(`{"e":"a@example.com","m":"email","i":1}`), []byte("session|a.example.com")), "session|a.example.com")
	f.Add("", "")
	f.Add(strings.Repeat("A", 40), "session|a.example.com")
	f.Fuzz(func(t *testing.T, sealed, aad string) {
		if _, err := box.Open(sealed, []byte(aad)); err != nil {
			return
		}
		if _, err := box.Open(sealed, []byte(aad+".evil.example.net")); err == nil {
			t.Errorf("%q opens for two hosts", sealed)
		}
		if _, err := New(secret, "pending").Open(sealed, []byte(aad)); err == nil {
			t.Errorf("%q opens for two purposes", sealed)
		}
	})
}
