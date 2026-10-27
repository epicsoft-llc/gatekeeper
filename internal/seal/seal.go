package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

var ErrInvalid = errors.New("sealed value is invalid")

// Each purpose gets its own key.
type Box struct {
	aead cipher.AEAD
}

func Key(secret []byte, purpose string) []byte {
	key, err := hkdf.Key(sha256.New, secret, nil, "gatekeeper "+purpose, 32)
	if err != nil {
		panic(err)
	}
	return key
}

func New(secret []byte, purpose string) *Box {
	block, err := aes.NewCipher(Key(secret, purpose))
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return &Box{aead: aead}
}

// Seal binds the value to aad: it opens only with the same aad, e.g. the host it was issued for.
func (b *Box) Seal(plain, aad []byte) string {
	nonce := make([]byte, b.aead.NonceSize(), b.aead.NonceSize()+len(plain)+b.aead.Overhead())
	rand.Read(nonce)
	return base64.RawURLEncoding.EncodeToString(b.aead.Seal(nonce, nonce, plain, aad))
}

func (b *Box) Open(sealed string, aad []byte) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(raw) < b.aead.NonceSize()+b.aead.Overhead() {
		return nil, ErrInvalid
	}
	size := b.aead.NonceSize()
	plain, err := b.aead.Open(nil, raw[:size], raw[size:], aad)
	if err != nil {
		return nil, ErrInvalid
	}
	return plain, nil
}
