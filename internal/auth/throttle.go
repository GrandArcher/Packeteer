package auth

import (
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

type failures struct {
	count int
	start time.Time
}

// failKey is what failed sign-ins are counted under: a user name and the
// client network. Behind a reverse proxy every client has the proxy's
// address; the user name keeps one client's guesses from locking out every
// user (#506). user is empty for a failure that names no valid user (a bad
// token, a malformed header), so those still share one count per network.
// An IPv6 client is counted per /64: one host usually holds the whole /64,
// so counting per address would give it 2^64 counts (#493).
type failKey struct {
	user string
	net  netip.Addr
}

func newFailKey(user string, ip netip.Addr) failKey {
	if !ValidUserName(user) {
		user = ""
	}
	if ip.Is6() {
		ip = netip.PrefixFrom(ip, 64).Masked().Addr()
	}
	return failKey{user: user, net: ip}
}

// Throttle counts failed sign-ins per user name and client network. Past
// failLimit failures in failWindow, Throttled reports true for that key
// until the window ends. The table is capped at maxFailKeys.
type Throttle struct {
	log   *slog.Logger
	mu    sync.Mutex
	fails map[failKey]*failures
}

// NewThrottle returns an empty Throttle. A nil log takes slog.Default.
func NewThrottle(log *slog.Logger) *Throttle {
	if log == nil {
		log = slog.Default()
	}
	return &Throttle{log: log, fails: map[failKey]*failures{}}
}

// Throttled reports whether user from ip is over the failure limit.
func (t *Throttle) Throttled(user string, ip netip.Addr, now time.Time) bool {
	return t.throttled(newFailKey(user, ip), now)
}

// Fail counts one failed sign-in for user from ip.
func (t *Throttle) Fail(user string, ip netip.Addr, now time.Time) {
	t.fail(newFailKey(user, ip), now)
}

func (t *Throttle) throttled(k failKey, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.fails[k]
	if f == nil {
		return false
	}
	if now.Sub(f.start) >= failWindow {
		delete(t.fails, k)
		return false
	}
	return f.count >= failLimit
}

func (t *Throttle) fail(k failKey, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.fails[k]; !ok && len(t.fails) >= maxFailKeys {
		t.evict(now)
	}
	f := t.fails[k]
	if f == nil || now.Sub(f.start) >= failWindow {
		f = &failures{start: now}
		t.fails[k] = f
	}
	f.count++
	if f.count == failLimit {
		t.log.Warn("http auth: too many failed sign-ins; throttling", "user", k.user, "remote", k.net.String(), "window", failWindow)
	}
}

// evict makes room for one count: expired ones first, else the one with
// the oldest window. Resetting a count that way takes maxFailKeys other
// failures, each a full password check, inside one window.
func (t *Throttle) evict(now time.Time) {
	var oldest failKey
	var of *failures
	for k, f := range t.fails {
		if now.Sub(f.start) >= failWindow {
			delete(t.fails, k)
			continue
		}
		if of == nil || f.start.Before(of.start) {
			oldest, of = k, f
		}
	}
	if len(t.fails) >= maxFailKeys {
		delete(t.fails, oldest)
	}
}
