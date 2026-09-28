// Package maintenance implements the "maintenance" policy: windows during
// which providers carry no improvements.
//
// A window is either recurring (a five-field cron schedule plus a
// duration) or one-off (start and end timestamps). Windows can also be
// opened on demand through the ops API; those live in memory only and end
// when the controller restarts. While a window is open, Decide treats its
// providers as excluded: improvements on them are retired and no new move
// may land on them. Native routing through the provider is left alone.
//
// The plugin does not announce and matches no prefixes.
package maintenance

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // the container image has no zoneinfo

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "maintenance"

// Bounds.
const (
	MinDuration           = time.Minute
	MaxDuration           = 7 * 24 * time.Hour
	DefaultMaxAPIDuration = 24 * time.Hour
	MaxWindows            = 1000
	// MaxAPIWindows caps windows opened on demand and still open.
	MaxAPIWindows = 100
)

func init() { plugin.Policies.Register(TypeName, New) }

// Config is the maintenance policy's config block.
type Config struct {
	// Timezone applies to schedules (IANA name, default UTC).
	Timezone string   `yaml:"timezone"`
	Windows  []Window `yaml:"windows"`
	// MaxAPIDuration caps a window opened through the API (default 24h,
	// at most 7 days).
	MaxAPIDuration time.Duration `yaml:"max_api_duration"`
}

// Window is one configured maintenance window. Set schedule and duration,
// or start and end.
type Window struct {
	Name      string        `yaml:"name"`
	Providers []string      `yaml:"providers"`
	Schedule  string        `yaml:"schedule"`
	Duration  time.Duration `yaml:"duration"`
	Start     string        `yaml:"start"`
	End       string        `yaml:"end"`
	Reason    string        `yaml:"reason"`
}

type window struct {
	name      string
	providers []string
	sched     *schedule
	dur       time.Duration
	start     time.Time
	end       time.Time
	reason    string
}

// Policy is the maintenance policy.
type Policy struct {
	plugin.Base
	loc       *time.Location
	windows   []window
	maxAPI    time.Duration
	providers map[string]bool

	mu     sync.Mutex
	nextID int
	api    []plugin.MaintenanceWindow
}

// New is the plugin factory. It does no I/O.
func New(c plugin.Config, env plugin.Env) (plugin.Policy, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	p := &Policy{loc: time.UTC, maxAPI: DefaultMaxAPIDuration}
	if env.Providers != nil {
		p.providers = map[string]bool{}
		for _, n := range env.Providers {
			p.providers[n] = true
		}
	}
	if tz := strings.TrimSpace(cfg.Timezone); tz != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			add("timezone %q: %v", tz, err)
		} else {
			p.loc = loc
		}
	}
	if cfg.MaxAPIDuration != 0 {
		if cfg.MaxAPIDuration < MinDuration || cfg.MaxAPIDuration > MaxDuration {
			add("max_api_duration %s must be between %s and %s", cfg.MaxAPIDuration, MinDuration, MaxDuration)
		}
		p.maxAPI = cfg.MaxAPIDuration
	}
	if len(cfg.Windows) > MaxWindows {
		add("windows: at most %d", MaxWindows)
	}
	names := map[string]bool{}
	for i, w := range cfg.Windows {
		label := fmt.Sprintf("windows[%d]", i)
		name := strings.TrimSpace(w.Name)
		if name == "" {
			name = label
		} else {
			label = fmt.Sprintf("windows[%d] (%s)", i, name)
		}
		if names[name] {
			add("%s: duplicate window name", label)
		}
		names[name] = true
		if err := p.checkProviders(w.Providers); err != nil {
			add("%s: %v", label, err)
		}
		cw := window{name: name, providers: slices.Clone(w.Providers), reason: w.Reason}
		sched := strings.TrimSpace(w.Schedule)
		switch {
		case sched != "" && (w.Start != "" || w.End != ""):
			add("%s: set schedule and duration, or start and end, not both", label)
		case sched != "":
			sc, err := parseSchedule(sched)
			if err != nil {
				add("%s: %v", label, err)
			}
			cw.sched = &sc
			if w.Duration < MinDuration || w.Duration > MaxDuration {
				add("%s: duration %s must be between %s and %s", label, w.Duration, MinDuration, MaxDuration)
			}
			cw.dur = w.Duration
		case w.Start != "" || w.End != "":
			if w.Duration != 0 {
				add("%s: duration is only for schedule windows", label)
			}
			s, err1 := time.Parse(time.RFC3339, w.Start)
			e, err2 := time.Parse(time.RFC3339, w.End)
			if err1 != nil || err2 != nil {
				add("%s: start and end must both be RFC 3339 timestamps", label)
			} else if !e.After(s) {
				add("%s: end must be after start", label)
			}
			cw.start, cw.end = s, e
		default:
			add("%s: set schedule and duration, or start and end", label)
		}
		p.windows = append(p.windows, cw)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Policy) checkProviders(names []string) error {
	if len(names) == 0 {
		return errors.New("at least one provider is required")
	}
	seen := map[string]bool{}
	for _, n := range names {
		if p.providers != nil && !p.providers[n] {
			return fmt.Errorf("provider %q is not configured", n)
		}
		if seen[n] {
			return fmt.Errorf("duplicate provider %q", n)
		}
		seen[n] = true
	}
	return nil
}

// Match never matches: maintenance is provider-wide, not per prefix.
func (p *Policy) Match(plugin.PolicySubject) (plugin.PolicyVerdict, bool) {
	return plugin.PolicyVerdict{}, false
}

// Active returns the windows open at now, sorted by start then name.
func (p *Policy) Active(now time.Time) []plugin.MaintenanceWindow {
	var out []plugin.MaintenanceWindow
	for _, w := range p.windows {
		mw := plugin.MaintenanceWindow{ID: "schedule-" + w.name, Name: w.name, Providers: slices.Clone(w.providers), Source: "schedule", Reason: w.reason}
		if w.sched != nil {
			start, ok := w.sched.lastStart(now, w.dur, p.loc)
			if !ok {
				continue
			}
			mw.Start, mw.End = start.UTC(), start.Add(w.dur).UTC()
		} else {
			if now.Before(w.start) || !now.Before(w.end) {
				continue
			}
			mw.Start, mw.End = w.start.UTC(), w.end.UTC()
		}
		out = append(out, mw)
	}
	p.mu.Lock()
	kept := p.api[:0]
	for _, w := range p.api {
		if !now.Before(w.End) {
			continue
		}
		kept = append(kept, w)
		if !now.Before(w.Start) {
			w.Providers = slices.Clone(w.Providers)
			out = append(out, w)
		}
	}
	p.api = kept
	p.mu.Unlock()
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].Start.Equal(out[j].Start) {
			return out[i].Start.Before(out[j].Start)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Open starts an on-demand window at now for d. It exists in memory only.
func (p *Policy) Open(providers []string, d time.Duration, reason string, now time.Time) (plugin.MaintenanceWindow, error) {
	if err := p.checkProviders(providers); err != nil {
		return plugin.MaintenanceWindow{}, err
	}
	if d < MinDuration || d > p.maxAPI {
		return plugin.MaintenanceWindow{}, fmt.Errorf("duration %s must be between %s and %s", d, MinDuration, p.maxAPI)
	}
	if len(reason) > 256 {
		return plugin.MaintenanceWindow{}, errors.New("reason is longer than 256 characters")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	open := 0
	for _, w := range p.api {
		if now.Before(w.End) {
			open++
		}
	}
	if open >= MaxAPIWindows {
		return plugin.MaintenanceWindow{}, fmt.Errorf("at most %d on-demand windows may be open", MaxAPIWindows)
	}
	p.nextID++
	w := plugin.MaintenanceWindow{
		ID: fmt.Sprintf("api-%d", p.nextID), Name: "on-demand", Providers: slices.Clone(providers),
		Start: now.UTC(), End: now.Add(d).UTC(), Source: "api", Reason: reason,
	}
	p.api = append(p.api, w)
	return w, nil
}

// Close ends an on-demand window. Configured windows cannot be closed.
func (p *Policy) Close(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, w := range p.api {
		if w.ID == id {
			p.api = append(p.api[:i], p.api[i+1:]...)
			return true
		}
	}
	return false
}
