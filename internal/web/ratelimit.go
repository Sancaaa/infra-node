package web

import (
	"sync"
	"time"
)

const (
	freeAttempts = 3                // wrong passwords allowed before any delay
	maxPenalty   = 15 * time.Minute // the delay never grows beyond this
	forgetAfter  = time.Hour        // a key with no failures for this long starts fresh
	maxTracked   = 1000             // hard cap on tracked keys; expired entries are dropped first, then the oldest
)

// loginLimiter slows down password guessing, per key: the client address for a
// login, "user:<id>" for the current-password check of Profile, so a stolen
// session cannot be used to guess the password there. It is headnode's
// (server/ratelimit.go), copied on purpose: the apps are separate programs.
//
// It lives in memory: a restart forgets everything, which is fine for
// something this simple.
type loginLimiter struct {
	mu    sync.Mutex
	byKey map[string]*failures
	now   func() time.Time // a field so tests can move the clock instead of sleeping
}

type failures struct {
	count int
	last  time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{byKey: make(map[string]*failures), now: time.Now}
}

// penalty is how long to wait after the count-th wrong password in a row:
// nothing for the first 3, then 1 s, 2 s, 4 s, ... up to 15 minutes. A person
// who mistypes twice never notices it. A script guessing passwords ends up
// with about 15 guesses per hour per address.
func penalty(count int) time.Duration {
	if count <= freeAttempts {
		return 0
	}
	shift := count - freeAttempts - 1
	if shift >= 10 { // 1<<10 s is already above the cap, and a bigger shift could overflow
		return maxPenalty
	}
	return min(time.Second<<shift, maxPenalty)
}

// begin says how long this key must still wait (0: it may try now). When it
// may try, the attempt is counted as a failure at once, before the password is
// checked, and a successful login undoes it with reset.
//
// Checking first and counting after the password check (about 50 ms of bcrypt)
// would let many attempts sent at the same moment all pass the check before the
// first one is counted: 500 at once would be 500 guesses, not 4.
func (l *loginLimiter) begin(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if wait := l.waitLocked(key); wait > 0 {
		return wait
	}
	l.failLocked(key)
	return 0
}

func (l *loginLimiter) waitLocked(key string) time.Duration {
	f, ok := l.byKey[key]
	if !ok {
		return 0
	}
	now := l.now()
	if now.Sub(f.last) > forgetAfter {
		delete(l.byKey, key)
		return 0
	}
	return max(0, f.last.Add(penalty(f.count)).Sub(now))
}

func (l *loginLimiter) failLocked(key string) {
	now := l.now()
	f := l.byKey[key]
	if f == nil {
		// Without a hard cap, someone using many addresses within one hour
		// could grow the table forever. Drop expired entries first; if still
		// at capacity, evict the oldest entry.
		if len(l.byKey) >= maxTracked {
			l.pruneLocked(now)
		}
		for len(l.byKey) >= maxTracked {
			l.evictOldestLocked()
		}
		f = &failures{}
		l.byKey[key] = f
	} else if now.Sub(f.last) > forgetAfter {
		f.count = 0
	}
	f.count++
	f.last = now
}

func (l *loginLimiter) pruneLocked(now time.Time) {
	for k, entry := range l.byKey {
		if now.Sub(entry.last) > forgetAfter {
			delete(l.byKey, k)
		}
	}
}

func (l *loginLimiter) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, entry := range l.byKey {
		if first || entry.last.Before(oldestTime) {
			oldestKey = k
			oldestTime = entry.last
			first = false
		}
	}
	if !first {
		delete(l.byKey, oldestKey)
	}
}

// reset forgets a key after a successful login.
func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.byKey, key)
}

// eventCap lets a limited number of "nobody is logged in" lines into History
// per minute. Those rows are written for anyone who can reach the page, so
// without a cap a script could fill the database with them. A real attack is
// still visible: the cap is far above what a person causes, and the log line
// of the server keeps counting.
type eventCap struct {
	mu     sync.Mutex
	window time.Time
	n      int
	now    func() time.Time
}

const anonymousPerMinute = 60

func (c *eventCap) allow() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if now.Sub(c.window) >= time.Minute {
		c.window, c.n = now, 0
	}
	if c.n >= anonymousPerMinute {
		return false
	}
	c.n++
	return true
}
