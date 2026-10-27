package limit

import (
	"sync"
	"time"
)

// Beyond maxKeys a new key pushes out an arbitrary one: refusing it would let a flood of keys lock out everybody.
type Limiter struct {
	mu      sync.Mutex
	count   int
	window  time.Duration
	maxKeys int
	entries map[string]*entry
}

type entry struct {
	start time.Time
	n     int
}

func New(count int, window time.Duration, maxKeys int) *Limiter {
	return &Limiter{count: count, window: window, maxKeys: maxKeys, entries: map[string]*entry{}}
}

func (l *Limiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e != nil && now.Sub(e.start) < l.window {
		if e.n >= l.count {
			return false
		}
		e.n++
		return true
	}
	if e == nil && len(l.entries) >= l.maxKeys {
		for victim := range l.entries {
			delete(l.entries, victim)
			break
		}
	}
	l.entries[key] = &entry{start: now, n: 1}
	return true
}

func (l *Limiter) Sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
}

func (l *Limiter) sweepLocked(now time.Time) {
	for key, e := range l.entries {
		if now.Sub(e.start) >= l.window {
			delete(l.entries, key)
		}
	}
}
