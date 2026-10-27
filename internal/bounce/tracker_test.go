package bounce

import (
	"crypto/rand"
	"regexp"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 27, 8, 0, 0, 0, time.UTC)

func TestSenderAndToken(t *testing.T) {
	if len(rand.Text()) != TokenLength {
		t.Fatalf("rand.Text() has %d characters, TokenLength says %d", len(rand.Text()), TokenLength)
	}
	tracker := NewTracker("gate@example.com", 48*time.Hour, 10)
	sender := tracker.Sender("reader@example.org", now)
	if !regexp.MustCompile(`^gate\+b-[a-z2-7]{26}@example\.com$`).MatchString(sender) {
		t.Fatalf("envelope sender %q", sender)
	}
	if other := tracker.Sender("reader@example.org", now); other == sender {
		t.Error("two mails share an envelope sender")
	}
	token, ok := tracker.Token(sender)
	if !ok || sender != "gate+b-"+token+"@example.com" {
		t.Fatalf("Token(%q) = %q, %v", sender, token, ok)
	}
	found := map[string]bool{
		"<" + sender + ">":                          true,
		`"Gate" <GATE+B-` + token + `@Example.COM>`: true,
		"x@example.org, " + sender:                  true,
		sender + ".evil.example.net":                false,
		"xgate+b-" + token + "@example.com":         false,
		"gate+b-short@example.com":                  false,
		"other+b-" + token + "@example.com":         false,
		"gate@example.com":                          false,
	}
	for value, want := range found {
		if got, ok := tracker.Token(value); ok != want || (ok && got != token) {
			t.Errorf("Token(%q) = %q, %v", value, got, ok)
		}
	}
}

func TestBounced(t *testing.T) {
	tracker := NewTracker("gate@example.com", 48*time.Hour, 10)
	token, _ := tracker.Token(tracker.Sender("reader@example.org", now))
	if _, ok := tracker.Bounced(token, "stranger@example.org", now); ok {
		t.Error("a bounce naming another address counted")
	}
	if _, ok := tracker.Bounced("abcdefghijklmnopqrstuvwxyz", "reader@example.org", now); ok {
		t.Error("a bounce with an unknown token counted")
	}
	until, ok := tracker.Bounced(token, "reader@example.org", now.Add(time.Hour))
	if !ok || !until.Equal(now.Add(49*time.Hour)) {
		t.Fatalf("Bounced = %v, %v", until, ok)
	}
	if !tracker.Suppressed("reader@example.org", now.Add(48*time.Hour)) || tracker.Suppressed("stranger@example.org", now) {
		t.Error("Suppressed")
	}
	if _, ok := tracker.Bounced(token, "reader@example.org", now.Add(2*time.Hour)); ok {
		t.Error("a token counted twice")
	}
	if tracker.Suppressed("reader@example.org", until) {
		t.Error("the suppression did not end")
	}

	late, _ := tracker.Token(tracker.Sender("late@example.org", now))
	if _, ok := tracker.Bounced(late, "late@example.org", now.Add(Keep)); ok {
		t.Error("a token outlived Keep")
	}
	tracker.Sweep(now.Add(Keep))
	if len(tracker.tokens) != 0 || len(tracker.suppressed) != 0 {
		t.Errorf("after the sweep: %d tokens, %d suppressed", len(tracker.tokens), len(tracker.suppressed))
	}
}

func TestTrackerIsBounded(t *testing.T) {
	tracker := NewTracker("gate@example.com", time.Hour, 3)
	first, _ := tracker.Token(tracker.Sender("a@example.org", now))
	tracker.Sender("b@example.org", now.Add(time.Second))
	tracker.Sender("c@example.org", now.Add(2*time.Second))
	last, _ := tracker.Token(tracker.Sender("d@example.org", now.Add(3*time.Second)))
	if len(tracker.tokens) != 3 {
		t.Errorf("%d tokens in a tracker of 3", len(tracker.tokens))
	}
	if _, ok := tracker.Bounced(first, "a@example.org", now.Add(4*time.Second)); ok {
		t.Error("a full tracker kept its oldest token")
	}
	if _, ok := tracker.Bounced(last, "d@example.org", now.Add(4*time.Second)); !ok {
		t.Error("the newest token was given up")
	}
}
