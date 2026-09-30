// Package lease is the built-in high-availability elector (#31): a lease
// file on storage both instances of an active/standby pair mount (a shared
// Docker volume on one host, or a shared filesystem with working POSIX
// locks). The active instance renews the lease every renew interval.
//
// Safety does not depend on synchronized clocks. The active instance stops
// being active ttl/2 after its last successful renewal started, measured on
// its own monotonic clock, whether or not its goroutine still runs. A
// standby takes the lease only after the record has not changed, on its
// own monotonic clock, for the longer of ttl and ttl/2 + route_hold +
// renew, where route_hold is the holder's longest negotiated BGP hold time
// written into every renewal. By then the holder has stopped announcing,
// and if it died without withdrawing, the routers have dropped its session
// and its routes (Packeteer never enables graceful restart). A holder that
// withdrew its routes resigns, and a standby takes over at its next renewal.
//
// Every read-modify-write of the record happens under an exclusive flock on
// a sibling lock file, and the record is replaced with an atomic rename.
// The plugin never announces.
package lease

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "lease"

// IDEnv names this instance when the config has no id.
const IDEnv = "PACKETEER_HA_ID"

// Defaults and limits.
const (
	DefaultTTL = 10 * time.Second
	MinTTL     = 2 * time.Second
	MaxTTL     = 5 * time.Minute
	MinRenew   = 100 * time.Millisecond
	// DefaultRouteHold is assumed when a record does not say how long the
	// holder's routes can outlive it: Packeteer's proposed BGP hold time.
	DefaultRouteHold = 90 * time.Second
)

func init() { plugin.Electors.Register(TypeName, New) }

// Config is the lease plugin's config block.
type Config struct {
	// Path is the lease file, on storage both instances mount. Required,
	// absolute. The lock file is Path + ".lock".
	Path string `yaml:"path"`
	// ID names this instance (default: $PACKETEER_HA_ID, then the
	// hostname). The two instances must use different IDs.
	ID string `yaml:"id"`
	// TTL is the lease time (default 10s, 2s–5m). The active instance
	// stops announcing TTL/2 after its last successful renewal.
	TTL time.Duration `yaml:"ttl"`
	// Renew is the renewal and standby poll interval (default TTL/5, at
	// most TTL/4, at least 100ms).
	Renew time.Duration `yaml:"renew"`
}

var idRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// record is the lease file.
type record struct {
	// Holder is the holding process's token: ID, '#', and a random nonce,
	// so a restarted instance does not mistake its predecessor's lease
	// for its own.
	Holder   string `json:"holder"`
	ID       string `json:"id"`
	Seq      uint64 `json:"seq"`
	Released bool   `json:"released,omitempty"`
	// RouteHoldMS is the holder's RouteHold at the last renewal.
	RouteHoldMS int64 `json:"route_hold_ms"`
	TTLMS       int64 `json:"ttl_ms"`
	// Time is the writer's wall clock, for operators only. Nothing reads
	// it for a decision.
	Time time.Time `json:"time"`
}

// Lease is the lease elector.
type Lease struct {
	plugin.Base
	path  string
	id    string
	token string
	ttl   time.Duration
	renew time.Duration
	log   *slog.Logger

	// opMu serializes file operations inside this process (tick, Resign).
	opMu sync.Mutex

	mu         sync.Mutex
	candidate  func() plugin.Candidacy
	onChange   func()
	active     bool
	lastOK     time.Time // start of the last successful renewal (monotonic)
	since      time.Time
	takeovers  int
	holder     string
	eligible   bool
	detail     string
	lastRaw    []byte
	lastChange time.Time // when this instance last saw the record change (monotonic)
	noAcquire  time.Time // Resign backs off acquisition until then

	changed chan struct{}
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	// failWrite makes writes fail (tests).
	failWrite func() error
}

// New builds a lease elector from config. It does no I/O.
func New(c plugin.Config, env plugin.Env) (plugin.Elector, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.Path == "" {
		return nil, errors.New("path is required (a file on storage both instances mount)")
	}
	if !filepath.IsAbs(cfg.Path) {
		return nil, fmt.Errorf("path %q must be absolute", cfg.Path)
	}
	if cfg.ID == "" && env.Getenv != nil {
		cfg.ID = env.Getenv(IDEnv)
	}
	if cfg.ID == "" {
		h, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("id is not set and the hostname is unavailable: %w", err)
		}
		cfg.ID = h
	}
	if !idRE.MatchString(cfg.ID) {
		return nil, fmt.Errorf("id %q must be 1-64 characters of letters, digits, '_', '.' or '-', starting with a letter or digit", cfg.ID)
	}
	if cfg.TTL == 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.TTL < MinTTL || cfg.TTL > MaxTTL {
		return nil, fmt.Errorf("ttl %s must be between %s and %s", cfg.TTL, MinTTL, MaxTTL)
	}
	if cfg.Renew == 0 {
		cfg.Renew = cfg.TTL / 5
	}
	if cfg.Renew < MinRenew || cfg.Renew*4 > cfg.TTL {
		return nil, fmt.Errorf("renew %s must be at least %s and at most ttl/4 (%s)", cfg.Renew, MinRenew, cfg.TTL/4)
	}
	return newLease(cfg, env.Logger)
}

func newLease(cfg Config, log *slog.Logger) (*Lease, error) {
	if log == nil {
		log = slog.Default()
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &Lease{
		path: cfg.Path, id: cfg.ID, token: cfg.ID + "#" + hex.EncodeToString(nonce),
		ttl: cfg.TTL, renew: cfg.Renew, log: log,
		candidate: func() plugin.Candidacy { return plugin.Candidacy{Eligible: true, RouteHold: DefaultRouteHold} },
		changed:   make(chan struct{}, 1),
	}, nil
}

// ID is this instance's ID.
func (l *Lease) ID() string { return l.id }

// SetCandidate implements plugin.Elector.
func (l *Lease) SetCandidate(fn func() plugin.Candidacy) {
	if fn == nil {
		return
	}
	l.mu.Lock()
	l.candidate = fn
	l.mu.Unlock()
}

// OnChange implements plugin.Elector.
func (l *Lease) OnChange(fn func()) {
	l.mu.Lock()
	l.onChange = fn
	l.mu.Unlock()
}

// Active implements plugin.Elector. It is false once ttl/2 has passed
// since the last successful renewal, even if the renew loop is stuck.
func (l *Lease) Active() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.activeLocked(time.Now())
}

func (l *Lease) activeLocked(now time.Time) bool {
	return l.active && now.Sub(l.lastOK) < l.ttl/2
}

// Start creates the lease directory and starts the renew loop.
func (l *Lease) Start(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return fmt.Errorf("lease directory: %w", err)
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	l.cancel = cancel
	l.mu.Lock()
	now := time.Now()
	l.lastChange, l.since = now, now
	l.detail = "starting"
	l.mu.Unlock()
	l.wg.Add(3)
	go func() {
		defer l.wg.Done()
		l.loop(ctx)
	}()
	go func() {
		defer l.wg.Done()
		l.watchdog(ctx)
	}()
	go func() {
		defer l.wg.Done()
		l.notifier(ctx)
	}()
	l.log.Info("ha lease elector started", "id", l.id, "path", l.path, "ttl", l.ttl, "renew", l.renew)
	return nil
}

// Stop ends the renew loop. It does not resign: a lease the core did not
// resign (its routes may still be on the wire) is left to run out.
func (l *Lease) Stop(ctx context.Context) error {
	if l.cancel == nil {
		return nil
	}
	l.cancel()
	// No change notification: the core has already withdrawn (and
	// resigned when it could) before plugins stop.
	l.mu.Lock()
	l.active, l.detail = false, "stopped"
	l.mu.Unlock()
	done := make(chan struct{})
	go func() {
		l.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *Lease) loop(ctx context.Context) {
	t := time.NewTicker(l.renew)
	defer t.Stop()
	for {
		l.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// watchdog turns Active's own deadline into a change notification, so the
// core withdraws even when the renew loop is stuck in file I/O.
func (l *Lease) watchdog(ctx context.Context) {
	t := time.NewTicker(l.renew / 2)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		l.mu.Lock()
		if l.active && !l.activeLocked(time.Now()) {
			l.log.Error("ha lease not renewed in time; stepping down", "id", l.id, "ttl", l.ttl)
			l.setActiveLocked(false, "lease renewal failed")
		}
		l.mu.Unlock()
	}
}

func (l *Lease) notifier(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.changed:
		}
		l.mu.Lock()
		fn := l.onChange
		l.mu.Unlock()
		if fn != nil {
			fn()
		}
	}
}

// setActiveLocked records a role change and wakes the notifier. The caller
// holds mu.
func (l *Lease) setActiveLocked(active bool, detail string) {
	l.detail = detail
	if l.active == active {
		return
	}
	l.active = active
	l.since = time.Now()
	if active {
		l.takeovers++
		l.log.Warn("ha: this instance is now active", "id", l.id, "detail", detail)
	} else {
		l.log.Warn("ha: this instance is now standby", "id", l.id, "detail", detail)
	}
	select {
	case l.changed <- struct{}{}:
	default:
	}
}

// wait is how long a standby leaves an unchanged record held by another
// instance before taking it.
func (l *Lease) wait(rec *record) time.Duration {
	ttl := l.ttl
	hold := DefaultRouteHold
	if rec != nil {
		if t := time.Duration(rec.TTLMS) * time.Millisecond; t > ttl {
			ttl = t
		}
		if h := time.Duration(rec.RouteHoldMS) * time.Millisecond; h > 0 {
			hold = h
		}
	}
	return max(ttl, ttl/2+hold+l.renew)
}

func (l *Lease) tick(ctx context.Context) {
	l.mu.Lock()
	candFn := l.candidate
	l.mu.Unlock()
	cand := candFn()
	start := time.Now()
	tctx, cancel := context.WithTimeout(ctx, l.renew)
	defer cancel()
	l.opMu.Lock()
	defer l.opMu.Unlock()
	err := withLock(tctx, l.path+".lock", func() error {
		rec, raw, err := l.read()
		if err != nil {
			return err
		}
		write, why := l.decide(rec, raw, cand)
		if !write {
			return nil
		}
		// No lock is held across the write: Active and the watchdog must
		// not wait on storage.
		out, err := l.write(rec, cand, false)
		if err != nil {
			return err
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		l.lastRaw, l.lastOK, l.holder = out, start, l.id
		l.setActiveLocked(true, why)
		return nil
	})
	if err != nil {
		l.mu.Lock()
		l.detail = "lease error: " + err.Error()
		l.mu.Unlock()
		if ctx.Err() == nil {
			l.log.Warn("ha lease", "id", l.id, "err", err)
		}
	}
}

// decide updates what this instance knows from the record just read and
// reports whether to write the record as its holder (renew or take over).
func (l *Lease) decide(rec *record, raw []byte, cand plugin.Candidacy) (write bool, why string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.eligible = cand.Eligible
	now := time.Now()
	if !bytes.Equal(raw, l.lastRaw) {
		l.lastRaw, l.lastChange = raw, now
		if rec == nil && raw != nil {
			l.log.Warn("ha lease file is not a lease record; treating it as held by an unknown instance", "path", l.path, "wait", l.wait(nil))
		}
	}
	l.holder = ""
	if rec != nil && !rec.Released {
		l.holder = holderName(rec)
	}
	if rec != nil && rec.Holder == l.token && !rec.Released {
		if now.Before(l.noAcquire) {
			// Resigned, but the release was not written: let the lease
			// run out rather than renew it.
			l.setActiveLocked(false, "resigned; lease left to run out")
			return false, ""
		}
		if cand.Eligible {
			return true, "lease held"
		}
		// The core withdraws on this change and then resigns.
		l.setActiveLocked(false, "not eligible (RIB view not ready)")
		return false, ""
	}
	if l.active {
		l.setActiveLocked(false, "lease held by "+holderName(rec))
	}
	switch {
	case !cand.Eligible:
		l.detail = "not eligible (RIB view not ready)"
		return false, ""
	case now.Before(l.noAcquire):
		l.detail = "resigned; not taking the lease back yet"
		return false, ""
	case raw == nil:
		return true, "lease was free"
	case rec != nil && rec.Released:
		return true, "lease released by " + holderName(rec)
	}
	// Held by another instance, or unreadable: wait until it has not
	// changed for long enough that its holder has stopped announcing and
	// its routes are gone.
	if w := l.wait(rec); now.Sub(l.lastChange) < w {
		l.detail = fmt.Sprintf("standby: lease held by %s (takeover after %s without renewal)", holderName(rec), w.Round(time.Millisecond))
		return false, ""
	}
	return true, "lease expired (held by " + holderName(rec) + ")"
}

func holderName(rec *record) string {
	if rec == nil || rec.ID == "" {
		return "an unknown instance"
	}
	return rec.ID
}

// read returns the record and the raw bytes: nil and nil when the file is
// missing. A file that cannot be parsed returns a nil record and its bytes;
// it counts as held, so a standby waits it out. Other read errors are
// returned and nothing is decided.
func (l *Lease) read() (*record, []byte, error) {
	raw, err := os.ReadFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if raw == nil {
		raw = []byte{}
	}
	var rec record
	if err := json.Unmarshal(raw, &rec); err != nil || rec.Holder == "" {
		return nil, raw, nil
	}
	return &rec, raw, nil
}

// write replaces the record with one held by this instance and returns the
// bytes written. The caller holds the file lock.
func (l *Lease) write(prev *record, cand plugin.Candidacy, released bool) ([]byte, error) {
	if l.failWrite != nil {
		if err := l.failWrite(); err != nil {
			return nil, err
		}
	}
	rec := record{Holder: l.token, ID: l.id, Released: released, TTLMS: l.ttl.Milliseconds(), Time: time.Now().UTC()}
	if prev != nil {
		rec.Seq = prev.Seq + 1
	}
	hold := cand.RouteHold
	if hold <= 0 {
		hold = DefaultRouteHold
	}
	rec.RouteHoldMS = hold.Milliseconds()
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(l.path, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// Resign implements plugin.Elector: it marks the lease released when this
// instance holds it, and does not take it back for one ttl.
func (l *Lease) Resign(ctx context.Context) error {
	l.mu.Lock()
	l.setActiveLocked(false, "resigned")
	l.noAcquire = time.Now().Add(l.ttl)
	candFn := l.candidate
	l.mu.Unlock()
	cand := candFn()
	l.opMu.Lock()
	defer l.opMu.Unlock()
	return withLock(ctx, l.path+".lock", func() error {
		rec, _, err := l.read()
		if err != nil || rec == nil || rec.Holder != l.token || rec.Released {
			return err
		}
		out, err := l.write(rec, cand, true)
		if err != nil {
			return err
		}
		l.mu.Lock()
		l.lastRaw, l.holder = out, ""
		l.mu.Unlock()
		l.log.Info("ha: lease released", "id", l.id)
		return nil
	})
}

// Status implements plugin.Elector.
func (l *Lease) Status() plugin.ElectorStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	role := plugin.RoleStandby
	if l.activeLocked(time.Now()) {
		role = plugin.RoleActive
	}
	return plugin.ElectorStatus{
		Type: TypeName, ID: l.id, Role: role, Since: l.since, Holder: l.holder,
		Eligible: l.eligible, Detail: l.detail, Takeovers: l.takeovers,
	}
}

// writeAtomic replaces path with data: a temporary file in the same
// directory, fsync, rename, and fsync of the directory.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".lease-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
