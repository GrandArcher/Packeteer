package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// FlapConfig is the flap quarantine (#228). A prefix whose chosen provider
// changes more than MaxFlips times in Window is withdrawn and held on its
// native path for a cool-down that doubles on each repeat offense, up to
// MaxCooldown. MaxFlips 0 turns it off.
type FlapConfig struct {
	MaxFlips    int
	Window      time.Duration
	Cooldown    time.Duration
	MaxCooldown time.Duration
}

func (f FlapConfig) enabled() bool { return f.MaxFlips > 0 }

// Quarantine actions on an Output.
const (
	QuarantineStart   = "quarantine"
	QuarantineRelease = "release"
)

// Quarantine is a prefix parked on its native path. Strikes is 1 for a
// first offense and grows while the prefix re-offends within MaxCooldown
// of its last release.
type Quarantine struct {
	Prefix  netip.Prefix `json:"prefix"`
	Since   time.Time    `json:"since"`
	Until   time.Time    `json:"until"`
	Flips   int          `json:"flips"`
	Strikes int          `json:"strikes"`
}

// QuarantineChange is a quarantine starting or ending, for events.
type QuarantineChange struct {
	Action     string
	Reason     string
	Quarantine Quarantine
}

// offense remembers a prefix's strikes after its quarantine ends, so the
// next cool-down is longer. It is forgotten MaxCooldown after last.
type offense struct {
	strikes int
	last    time.Time
}

// flapReason is the text on the decision and the retire of a quarantined
// prefix.
func flapReason(q Quarantine) string {
	return fmt.Sprintf("flap quarantine: %d provider changes, native path until %s", q.Flips, q.Until.Format(time.RFC3339))
}

// recentFlips drops flips older than the window and counts the rest.
func (s *State) recentFlips(p netip.Prefix, now time.Time, cfg FlapConfig) int {
	times := s.flips[p]
	i := 0
	for i < len(times) && now.Sub(times[i]) >= cfg.Window {
		i++
	}
	if i == len(times) {
		delete(s.flips, p)
		return 0
	}
	if i > 0 {
		s.flips[p] = slices.Clone(times[i:])
	}
	return len(times) - i
}

// flapNext reports whether one more provider change for p would pass
// MaxFlips.
func (s *State) flapNext(p netip.Prefix, now time.Time, cfg FlapConfig) bool {
	return cfg.enabled() && s.recentFlips(p, now, cfg)+1 > cfg.MaxFlips
}

func (s *State) noteFlip(p netip.Prefix, now time.Time, cfg FlapConfig) {
	if cfg.enabled() {
		s.flips[p] = append(s.flips[p], now)
	}
}

// quarantinePrefix parks p. Its flip history restarts at release.
func (s *State) quarantinePrefix(p netip.Prefix, now time.Time, cfg FlapConfig, out *Output) Quarantine {
	flips := s.recentFlips(p, now, cfg) + 1
	o := s.offenses[p]
	if o.strikes > 0 && now.Sub(o.last) > cfg.MaxCooldown {
		o.strikes = 0
	}
	o.strikes++
	cool := cfg.Cooldown
	for i := 1; i < o.strikes && cool < cfg.MaxCooldown; i++ {
		cool *= 2
	}
	cool = min(cool, cfg.MaxCooldown)
	q := Quarantine{Prefix: p, Since: now, Until: now.Add(cool), Flips: flips, Strikes: o.strikes}
	o.last = q.Until
	s.offenses[p] = o
	s.quarantine[p] = q
	delete(s.flips, p)
	out.Quarantines = append(out.Quarantines, QuarantineChange{Action: QuarantineStart, Reason: flapReason(q), Quarantine: q})
	return q
}

// releaseQuarantine ends q's quarantine and starts the strike memory from
// now.
func (s *State) releaseQuarantine(p netip.Prefix, now time.Time) {
	delete(s.quarantine, p)
	if o, ok := s.offenses[p]; ok {
		o.last = now
		s.offenses[p] = o
	}
}

// expireFlap releases quarantines that have run out, or all of them when
// the feature is off, and forgets history that can no longer matter.
func (s *State) expireFlap(now time.Time, cfg FlapConfig, out *Output) {
	ps := make([]netip.Prefix, 0, len(s.quarantine))
	for p := range s.quarantine {
		ps = append(ps, p)
	}
	sortPrefixes(ps)
	for _, p := range ps {
		q := s.quarantine[p]
		switch {
		case !cfg.enabled():
			s.releaseQuarantine(p, now)
			out.Quarantines = append(out.Quarantines, QuarantineChange{Action: QuarantineRelease, Reason: "flap quarantine is off", Quarantine: q})
		case !now.Before(q.Until):
			s.releaseQuarantine(p, q.Until)
			out.Quarantines = append(out.Quarantines, QuarantineChange{Action: QuarantineRelease, Reason: "cool-down elapsed", Quarantine: q})
		}
	}
	for p := range s.flips {
		if !cfg.enabled() {
			delete(s.flips, p)
			continue
		}
		s.recentFlips(p, now, cfg)
	}
	for p, o := range s.offenses {
		if _, held := s.quarantine[p]; !held && (!cfg.enabled() || now.Sub(o.last) > cfg.MaxCooldown) {
			delete(s.offenses, p)
		}
	}
}
