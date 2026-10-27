package limit

import (
	"strconv"
	"testing"
	"time"
)

func TestWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := New(3, time.Minute, 100)
	for i := 0; i < 3; i++ {
		if !l.Allow("a", start.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("request %d refused", i+1)
		}
	}
	if l.Allow("a", start.Add(10*time.Second)) {
		t.Error("fourth request in the window allowed")
	}
	if !l.Allow("b", start.Add(10*time.Second)) {
		t.Error("another key is limited too")
	}
	if !l.Allow("a", start.Add(time.Minute)) {
		t.Error("the next window is still limited")
	}
}

func TestMaxKeys(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := New(1, time.Minute, 3)
	for i := 0; i < 3; i++ {
		l.Allow(strconv.Itoa(i), start)
	}
	if !l.Allow("new", start.Add(time.Second)) || len(l.entries) != 3 {
		t.Errorf("a new key in a full limiter: %d entries", len(l.entries))
	}
	if l.Allow("new", start.Add(2*time.Second)) {
		t.Error("the new key got a second request in its window")
	}
	l.Sweep(start.Add(3 * time.Minute))
	if len(l.entries) != 0 {
		t.Errorf("%d entries left after the sweep", len(l.entries))
	}
}
