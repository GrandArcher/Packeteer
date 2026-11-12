// Package pin keeps the prefix pins an operator sets through the API
// (#558). A pin is a static policy verdict for one prefix: Decide steers it
// to the pinned provider under the same rails as a configured static rule
// (usable path, loss and latency ceiling, allowlist in inject, hold_time,
// the cap, flap quarantine), and the announcer adds the community and
// NO_EXPORT. A pin is refused unless the prefix is inside the allowlist and
// in the learned RIB view when it is set. Pins end at their expiry; with a
// store that keeps them (#565) a restart restores the ones not expired.
// The package announces nothing.
package pin

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Bounds.
const (
	MaxPins     = 100
	MinDuration = time.Minute
	MaxDuration = 7 * 24 * time.Hour
	MaxReason   = 200
)

// ErrConflict is a pin refused because of the pins already set: the prefix
// has one, or MaxPins are set.
var ErrConflict = errors.New("pin conflict")

// Pin is one prefix pinned to a provider.
type Pin struct {
	ID       string       `json:"id"`
	Prefix   netip.Prefix `json:"prefix"`
	Provider string       `json:"provider"`
	// MaxLossPct and MaxRTTMs are the ceiling the pinned path must stay
	// inside, as on a static rule. MaxRTTMs 0 is no latency ceiling.
	MaxLossPct float64   `json:"max_loss_pct"`
	MaxRTTMs   float64   `json:"max_rtt_ms,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	By         string    `json:"by,omitempty"`
	Created    time.Time `json:"created"`
	Expires    time.Time `json:"expires"`
}

// Request asks for a pin lasting Duration from now.
type Request struct {
	Prefix     netip.Prefix
	Provider   string
	MaxLossPct float64
	MaxRTTMs   float64
	Duration   time.Duration
	Reason     string
	By         string
}

// Rails is what a new pin is checked against, read when it is requested.
type Rails struct {
	Providers []string
	Allowlist []netip.Prefix
	// Learned reports whether the exact prefix is in the learned RIB view.
	Learned func(netip.Prefix) bool
}

// Store holds the pins. It is safe for concurrent use.
type Store struct {
	mu   sync.Mutex
	next int
	pins map[netip.Prefix]Pin
}

// NewStore returns an empty store.
func NewStore() *Store { return &Store{pins: map[netip.Prefix]Pin{}} }

// Add sets a pin after checking r against rails.
func (s *Store) Add(r Request, rails Rails, now time.Time) (Pin, error) {
	if err := r.check(rails); err != nil {
		return Pin{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(now)
	if old, ok := s.pins[r.Prefix]; ok {
		return Pin{}, fmt.Errorf("%w: %s is already pinned (%s)", ErrConflict, r.Prefix, old.ID)
	}
	if len(s.pins) >= MaxPins {
		return Pin{}, fmt.Errorf("%w: at most %d pins", ErrConflict, MaxPins)
	}
	s.next++
	p := Pin{ID: "pin-" + strconv.Itoa(s.next), Prefix: r.Prefix, Provider: r.Provider, MaxLossPct: r.MaxLossPct, MaxRTTMs: r.MaxRTTMs,
		Reason: r.Reason, By: r.By, Created: now.UTC(), Expires: now.Add(r.Duration).UTC()}
	s.pins[r.Prefix] = p
	return p, nil
}

func (r Request) check(rails Rails) error {
	p := r.Prefix
	switch {
	case !p.IsValid():
		return errors.New("prefix is required")
	case p != p.Masked():
		return fmt.Errorf("prefix %s has host bits set; use %s", p, p.Masked())
	case p.Bits() == 0:
		return errors.New("the default route is never steered")
	case !slices.Contains(rails.Providers, r.Provider):
		return fmt.Errorf("provider %q is not configured", r.Provider)
	case math.IsNaN(r.MaxLossPct) || r.MaxLossPct < 0 || r.MaxLossPct > 100:
		return errors.New("max_loss_pct must be 0-100")
	case math.IsNaN(r.MaxRTTMs) || math.IsInf(r.MaxRTTMs, 0) || r.MaxRTTMs < 0:
		return errors.New("max_rtt_ms must not be negative")
	case r.Duration < MinDuration || r.Duration > MaxDuration:
		return fmt.Errorf("duration %s must be between %s and %s", r.Duration, MinDuration, MaxDuration)
	case len(r.Reason) > MaxReason:
		return fmt.Errorf("reason must be at most %d bytes", MaxReason)
	case !netpfx.CoveredBy(rails.Allowlist, p):
		return fmt.Errorf("%s is not inside allowlist.prefixes", p)
	case rails.Learned == nil || !rails.Learned(p):
		return fmt.Errorf("%s is not in the learned RIB view", p)
	}
	return nil
}

// Restore replaces the pins with saved ones (#565). A saved pin is
// dropped when it has expired, it lasts longer than MaxDuration, its
// provider is no longer configured, its prefix is outside the allowlist,
// or MaxPins are already kept. The learned RIB view is not read: it is
// empty at start, and Decide and the announcer check it on every round.
// Restore returns why each was dropped.
func (s *Store) Restore(saved []Pin, rails Rails, now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pins = map[netip.Prefix]Pin{}
	var dropped []string
	for _, p := range saved {
		// A dropped pin's id is not given out again: history and the
		// audit log name it.
		if n, err := strconv.Atoi(strings.TrimPrefix(p.ID, "pin-")); err == nil && n > s.next {
			s.next = n
		}
		_, dup := s.pins[p.Prefix]
		why := ""
		switch {
		case !p.Prefix.IsValid() || p.Prefix != p.Prefix.Masked() || p.Prefix.Bits() == 0:
			why = "invalid prefix"
		case !now.Before(p.Expires):
			why = "expired"
		case p.Expires.After(p.Created.Add(MaxDuration)):
			why = "longer than " + MaxDuration.String()
		case !slices.Contains(rails.Providers, p.Provider):
			why = "provider " + strconv.Quote(p.Provider) + " is not configured"
		case !netpfx.CoveredBy(rails.Allowlist, p.Prefix):
			why = "outside allowlist.prefixes"
		case dup:
			why = "prefix pinned twice"
		case len(s.pins) >= MaxPins:
			why = "more than " + strconv.Itoa(MaxPins) + " pins"
		}
		if why != "" {
			dropped = append(dropped, p.ID+" "+p.Prefix.String()+": "+why)
			continue
		}
		s.pins[p.Prefix] = p
	}
	return dropped
}

// Remove deletes the pin with that id.
func (s *Store) Remove(id string) (Pin, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, p := range s.pins {
		if p.ID == id {
			delete(s.pins, k)
			return p, true
		}
	}
	return Pin{}, false
}

// List returns the pins not yet expired, sorted by prefix.
func (s *Store) List(now time.Time) []Pin {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(now)
	out := make([]Pin, 0, len(s.pins))
	for _, k := range netpfx.SortedKeys(s.pins) {
		out = append(out, s.pins[k])
	}
	return out
}

// Verdicts is each pinned prefix's static verdict. Nil when none is set.
func (s *Store) Verdicts(now time.Time) map[netip.Prefix]plugin.PolicyVerdict {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(now)
	if len(s.pins) == 0 {
		return nil
	}
	out := make(map[netip.Prefix]plugin.PolicyVerdict, len(s.pins))
	for k, p := range s.pins {
		out[k] = plugin.PolicyVerdict{Action: plugin.PolicyStatic, Providers: []string{p.Provider}, Rule: "api " + p.ID, Match: "prefix " + k.String(),
			MaxLossPct: p.MaxLossPct, MaxRTT: time.Duration(p.MaxRTTMs * float64(time.Millisecond))}
	}
	return out
}

func (s *Store) expire(now time.Time) {
	for k, p := range s.pins {
		if !now.Before(p.Expires) {
			delete(s.pins, k)
		}
	}
}
