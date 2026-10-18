// Package birdseye is the ixp.routeservers plugin (#164, #165). It polls
// Birdseye on each route server with GET only, keeps a short per-session
// history, and emits events when a route server, a member session, a
// max_prefix share, a filtered share, or a hijack, leak, or blackhole
// signal changes. It does not announce, it
// does not write the RIB view, and it is not an input to Decide.
package birdseye

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "birdseye"

// Defaults and bounds. A zero value in config selects the default.
const (
	DefaultInterval         = 5 * time.Minute
	minInterval             = time.Minute
	maxInterval             = time.Hour
	DefaultTimeout          = 15 * time.Second
	minTimeout              = time.Second
	maxTimeout              = 2 * time.Minute
	DefaultWorkers          = 4
	maxWorkers              = 8
	DefaultMaxBytes         = 8 << 20
	minMaxBytes             = 1024
	maxMaxBytes             = 32 << 20
	DefaultMaxPrefixWarnPct = 90
	DefaultFilteredWarnPct  = 50
	DefaultSpikeMin         = 10
	DefaultSpikeFactor      = 2
	DefaultBurstMin         = 20
	maxSpikeMin             = 1 << 20
	maxSpikeFactor          = 1000

	// maxServers and maxSessions bound the live sessions. A session keeps
	// maxSamples samples of 56 bytes plus up to maxReasons reason counts
	// each, and the history of a session that left stays for the whole
	// window, so churn can hold more than maxSessions histories per server.
	maxServers  = 8
	maxSessions = 2048
	maxSamples  = 288
	// maxReasons bounds the distinct rs-asn:1101:x values kept per session.
	maxReasons = 64

	// staleFactor intervals without a successful poll drop a server's
	// sessions from the view.
	staleFactor = 3
	// failsBeforeAlert consecutive failed polls raise ixp.rs_unreachable.
	failsBeforeAlert = 2
	// maxTrackedRoutes bounds the accepted routes a server's sessions
	// keep for the origin and more-specific signals (about 60 bytes each).
	maxTrackedRoutes = 250000
	// baselineSamples is how many earlier polls set the level a filtered
	// reason is compared with.
	baselineSamples = 12
)

// errNoRedirect refuses every redirect, so a poll never leaves the
// configured host.
var errNoRedirect = errors.New("redirects are not followed")

// ServerConfig is one route server.
type ServerConfig struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	ASN  uint32 `yaml:"asn"`
}

// Config is the birdseye plugin's config block.
type Config struct {
	Servers          []ServerConfig `yaml:"servers"`
	Interval         time.Duration  `yaml:"interval"`
	Timeout          time.Duration  `yaml:"timeout"`
	Workers          int            `yaml:"workers"`
	MaxBytes         int            `yaml:"max_bytes"`
	MaxPrefixWarnPct int            `yaml:"max_prefix_warn_pct"`
	FilteredWarnPct  int            `yaml:"filtered_warn_pct"`
	RouteSignals     bool           `yaml:"route_signals"`
	SpikeMin         int            `yaml:"spike_min"`
	SpikeFactor      int            `yaml:"spike_factor"`
	BurstMin         int            `yaml:"burst_min"`
}

func init() { plugin.RouteServerWatches.Register(TypeName, New) }

// The controller stores the watch as a RouteServerWatch.
var _ plugin.RouteServerWatch = (*Watch)(nil)

// Watch is the birdseye route-server watch.
type Watch struct {
	log      *slog.Logger
	interval time.Duration
	workers  int
	maxBytes int64
	prefPct  int
	filtPct  int
	signals  bool
	spikeMin int
	spikeX   int
	burstMin int
	// maxTracked caps the accepted routes kept per server.
	maxTracked int
	http       *http.Client
	servers    []*server

	mu      sync.Mutex
	members func() plugin.MemberView
	sink    func(plugin.Event)
	cancel  context.CancelFunc
	done    chan struct{}
}

// New validates the config. It does not dial.
func New(c plugin.Config, env plugin.Env) (plugin.RouteServerWatch, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if err := applyDefaults(&cfg); err != nil {
		return nil, err
	}
	servers, err := buildServers(cfg.Servers)
	if err != nil {
		return nil, err
	}
	log := env.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Watch{
		log:        log,
		interval:   cfg.Interval,
		workers:    cfg.Workers,
		maxBytes:   int64(cfg.MaxBytes),
		prefPct:    cfg.MaxPrefixWarnPct,
		filtPct:    cfg.FilteredWarnPct,
		signals:    cfg.RouteSignals,
		spikeMin:   cfg.SpikeMin,
		spikeX:     cfg.SpikeFactor,
		burstMin:   cfg.BurstMin,
		maxTracked: maxTrackedRoutes,
		servers:    servers,
		http: &http.Client{
			Timeout: cfg.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errNoRedirect
			},
		},
	}, nil
}

func applyDefaults(cfg *Config) error {
	if cfg.Interval == 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Interval < minInterval || cfg.Interval > maxInterval {
		return fmt.Errorf("interval %s must be between %s and %s", cfg.Interval, minInterval, maxInterval)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Timeout < minTimeout || cfg.Timeout > maxTimeout {
		return fmt.Errorf("timeout %s must be between %s and %s", cfg.Timeout, minTimeout, maxTimeout)
	}
	if cfg.Workers == 0 {
		cfg.Workers = DefaultWorkers
	}
	if cfg.Workers < 1 || cfg.Workers > maxWorkers {
		return fmt.Errorf("workers %d must be between 1 and %d", cfg.Workers, maxWorkers)
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}
	if cfg.MaxBytes < minMaxBytes || cfg.MaxBytes > maxMaxBytes {
		return fmt.Errorf("max_bytes %d must be between %d and %d", cfg.MaxBytes, minMaxBytes, maxMaxBytes)
	}
	if cfg.MaxPrefixWarnPct == 0 {
		cfg.MaxPrefixWarnPct = DefaultMaxPrefixWarnPct
	}
	if cfg.MaxPrefixWarnPct < 1 || cfg.MaxPrefixWarnPct > 100 {
		return fmt.Errorf("max_prefix_warn_pct %d must be between 1 and 100", cfg.MaxPrefixWarnPct)
	}
	if cfg.FilteredWarnPct == 0 {
		cfg.FilteredWarnPct = DefaultFilteredWarnPct
	}
	if cfg.FilteredWarnPct < 1 || cfg.FilteredWarnPct > 100 {
		return fmt.Errorf("filtered_warn_pct %d must be between 1 and 100", cfg.FilteredWarnPct)
	}
	if cfg.SpikeMin == 0 {
		cfg.SpikeMin = DefaultSpikeMin
	}
	if cfg.SpikeMin < 1 || cfg.SpikeMin > maxSpikeMin {
		return fmt.Errorf("spike_min %d must be between 1 and %d", cfg.SpikeMin, maxSpikeMin)
	}
	if cfg.SpikeFactor == 0 {
		cfg.SpikeFactor = DefaultSpikeFactor
	}
	if cfg.SpikeFactor < 1 || cfg.SpikeFactor > maxSpikeFactor {
		return fmt.Errorf("spike_factor %d must be between 1 and %d", cfg.SpikeFactor, maxSpikeFactor)
	}
	if cfg.BurstMin == 0 {
		cfg.BurstMin = DefaultBurstMin
	}
	if cfg.BurstMin < 1 || cfg.BurstMin > maxTrackedRoutes {
		return fmt.Errorf("burst_min %d must be between 1 and %d", cfg.BurstMin, maxTrackedRoutes)
	}
	return nil
}

func buildServers(in []ServerConfig) ([]*server, error) {
	if len(in) == 0 {
		return nil, errors.New("servers is required")
	}
	if len(in) > maxServers {
		return nil, fmt.Errorf("servers: more than %d", maxServers)
	}
	seen := map[string]bool{}
	out := make([]*server, 0, len(in))
	for i, sc := range in {
		p := fmt.Sprintf("servers[%d]", i)
		if !plugin.ValidLabel(sc.Name) {
			return nil, fmt.Errorf("%s.name is invalid", p)
		}
		if seen[sc.Name] {
			return nil, fmt.Errorf("%s.name %q is duplicated", p, sc.Name)
		}
		seen[sc.Name] = true
		if sc.ASN == 0 {
			return nil, fmt.Errorf("%s.asn is required", p)
		}
		base, err := baseURL(sc.URL)
		if err != nil {
			return nil, fmt.Errorf("%s.url: %w", p, err)
		}
		out = append(out, newServer(sc, base))
	}
	return out, nil
}

// baseURL accepts an http or https origin, or a subdirectory install. The
// query and userinfo are refused: Birdseye is read without a key, and the
// IXP Manager API key is never sent to it.
func baseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery {
		return "", errors.New("must be an http or https URL with a host and no userinfo, query, or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

// SetMembers records the IX-F view. The controller calls it before Start.
func (w *Watch) SetMembers(fn func() plugin.MemberView) {
	w.mu.Lock()
	w.members = fn
	w.mu.Unlock()
}

// SetEventSink records where events go. The controller calls it before Start.
func (w *Watch) SetEventSink(fn func(plugin.Event)) {
	w.mu.Lock()
	w.sink = fn
	w.mu.Unlock()
}

// Start polls once, then on each interval. It does not block.
func (w *Watch) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	w.mu.Lock()
	w.cancel = cancel
	w.done = done
	w.mu.Unlock()
	go w.loop(ctx, done)
	return nil
}

func (w *Watch) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	w.round(ctx, time.Now())
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			w.round(ctx, now)
		}
	}
}

// Stop cancels the loop and waits for it to leave.
func (w *Watch) Stop(ctx context.Context) error {
	w.mu.Lock()
	cancel, done := w.cancel, w.done
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
