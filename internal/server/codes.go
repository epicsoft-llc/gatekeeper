package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

type verdict int

const (
	accepted verdict = iota
	wrong
	gone
)

// An entry without email belongs to an address without access: never accepted, but it looks the same from outside -
// also in being replaced by the next request for the same address and host.
type codeStore struct {
	mu       sync.Mutex
	key      []byte
	ttl      time.Duration
	attempts int
	maxItems int
	items    map[string]*pendingCode
}

type pendingCode struct {
	email   string
	who     string
	host    string
	mac     []byte
	expires time.Time
	tries   int
}

func newCodeStore(key []byte, ttl time.Duration, attempts, maxItems int) *codeStore {
	return &codeStore{key: key, ttl: ttl, attempts: attempts, maxItems: maxItems, items: map[string]*pendingCode{}}
}

// issue keeps the entry of an address without access in the same way; a full store gives up its oldest entry.
func (s *codeStore) issue(address, host string, allowed bool, now time.Time) (id, code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	who := hex.EncodeToString(s.mac("who", address+"|"+host))
	for key, item := range s.items {
		if item.who == who || !now.Before(item.expires) {
			delete(s.items, key)
		}
	}
	if len(s.items) >= s.maxItems {
		oldest := ""
		for key, item := range s.items {
			if oldest == "" || item.expires.Before(s.items[oldest].expires) {
				oldest = key
			}
		}
		delete(s.items, oldest)
	}
	number, err := rand.Int(rand.Reader, big.NewInt(100_000_000))
	if err != nil {
		panic(err)
	}
	id, code = rand.Text(), fmt.Sprintf("%08d", number.Int64())
	item := &pendingCode{who: who, host: host, mac: s.mac(id, code), expires: now.Add(s.ttl)}
	if allowed {
		item.email = address
	}
	s.items[id] = item
	return id, code
}

func (s *codeStore) verify(id, host, input string, now time.Time) (string, verdict) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok || item.host != host {
		return "", gone
	}
	if !now.Before(item.expires) {
		delete(s.items, id)
		return "", gone
	}
	item.tries++
	code := strings.NewReplacer(" ", "", "-", "").Replace(input)
	if len(code) == 8 && onlyDigits(code) && hmac.Equal(s.mac(id, code), item.mac) && item.email != "" {
		delete(s.items, id)
		return item.email, accepted
	}
	if item.tries >= s.attempts {
		delete(s.items, id)
		return item.email, gone
	}
	return "", wrong
}

func (s *codeStore) sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
}

func (s *codeStore) sweepLocked(now time.Time) {
	for key, item := range s.items {
		if !now.Before(item.expires) {
			delete(s.items, key)
		}
	}
}

func (s *codeStore) mac(id, code string) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte(id + ":" + code))
	return h.Sum(nil)
}

func onlyDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
