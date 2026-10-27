package bounce

import (
	"crypto/rand"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Keep is how long a token waits for its bounce: a mail server gives up on a mail after some days and only then bounces it.
const Keep = 7 * 24 * time.Hour

// TokenLength is the length of rand.Text(); the token goes lower case into the envelope sender.
const TokenLength = 26

// Tracker gives every code mail an envelope sender of its own and counts only bounces that come back to one.
type Tracker struct {
	mu         sync.Mutex
	local      string
	domain     string
	suppress   time.Duration
	pattern    *regexp.Regexp
	tokens     map[string]sent
	suppressed map[string]time.Time
	maxItems   int
}

type sent struct {
	address string
	at      time.Time
}

// NewTracker takes mail.from as the configuration checked it: a plain lower case address.
func NewTracker(from string, suppress time.Duration, maxItems int) *Tracker {
	at := strings.LastIndexByte(from, '@')
	local, domain := from[:at], from[at+1:]
	return &Tracker{
		local:      local,
		domain:     domain,
		suppress:   suppress,
		pattern:    regexp.MustCompile(`(?i)(?:^|[^a-z0-9._+-])` + regexp.QuoteMeta(local) + `\+b-([a-z2-7]{26})@` + regexp.QuoteMeta(domain) + `(?:$|[^a-z0-9.-])`),
		tokens:     map[string]sent{},
		suppressed: map[string]time.Time{},
		maxItems:   maxItems,
	}
}

// Sender is the envelope sender of one mail to address. A full tracker gives up its oldest token.
func (t *Tracker) Sender(address string, now time.Time) string {
	token := strings.ToLower(rand.Text())
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.tokens) >= t.maxItems {
		t.sweepLocked(now)
	}
	if len(t.tokens) >= t.maxItems {
		oldest := ""
		for key, s := range t.tokens {
			if oldest == "" || s.at.Before(t.tokens[oldest].at) {
				oldest = key
			}
		}
		delete(t.tokens, oldest)
	}
	t.tokens[token] = sent{address: address, at: now}
	return t.local + "+b-" + token + "@" + t.domain
}

// Token finds the token of an address like the envelope senders of Sender in a header value.
func (t *Tracker) Token(value string) (string, bool) {
	match := t.pattern.FindStringSubmatch(value)
	if match == nil {
		return "", false
	}
	return strings.ToLower(match[1]), true
}

// Bounced counts a bounce only for a known token and the address that token was sent to; it suppresses that address.
func (t *Tracker) Bounced(token, recipient string, now time.Time) (time.Time, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.tokens[token]
	if !ok || s.address != recipient || now.Sub(s.at) >= Keep {
		return time.Time{}, false
	}
	delete(t.tokens, token)
	until := now.Add(t.suppress)
	if len(t.suppressed) >= t.maxItems {
		t.sweepLocked(now)
	}
	if len(t.suppressed) < t.maxItems {
		t.suppressed[s.address] = until
	}
	return until, true
}

func (t *Tracker) Suppressed(address string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	until, ok := t.suppressed[address]
	return ok && now.Before(until)
}

func (t *Tracker) Sweep(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked(now)
}

func (t *Tracker) sweepLocked(now time.Time) {
	for token, s := range t.tokens {
		if now.Sub(s.at) >= Keep {
			delete(t.tokens, token)
		}
	}
	for address, until := range t.suppressed {
		if !now.Before(until) {
			delete(t.suppressed, address)
		}
	}
}
