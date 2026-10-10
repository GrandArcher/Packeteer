package upgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Refusals the API maps to a status. Each leaves everything as it was.
var (
	ErrDisabled   = errors.New("upgrade is not enabled (upgrade.enabled)")
	ErrNoConfirm  = errors.New("an upgrade needs explicit confirmation")
	ErrBusy       = errors.New("an upgrade or rollback is already in progress")
	ErrBadTag     = errors.New("that is not a release version")
	ErrNotFound   = errors.New("that release was not found")
	ErrNotInstall = errors.New("that release has no signed binary for this platform")
	ErrSame       = errors.New("that version is already running")
	ErrVerify     = errors.New("release verification failed")
	ErrTrial      = errors.New("the new version did not pass its start check")
	ErrHA         = errors.New("high availability guard")
	ErrNoPrevious = errors.New("there is no previous version to roll back to")
	ErrFetch      = errors.New("could not read the release")
)

// Request is an apply or rollback request.
type Request struct {
	// Tag is the release to upgrade to. Unused by rollback.
	Tag string `json:"tag"`
	// Confirm must be true: the operator has seen what happens.
	Confirm bool `json:"confirm"`
	// StandbyUpgraded confirms that, in an HA pair, the standby already
	// runs the target version. Only asked of the active node.
	StandbyUpgraded bool `json:"standby_upgraded"`
}

// Result describes a switch that has been prepared and will start.
type Result struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Message string `json:"message"`
}

// VersionInfo is one runnable version.
type VersionInfo struct {
	Version string `json:"version"`
	Staged  bool   `json:"staged"`
}

// ReleaseInfo is a release as the page shows it.
type ReleaseInfo struct {
	Release
	Installable bool `json:"installable"`
	Newer       bool `json:"newer"`
	Current     bool `json:"current"`
}

// Status is what the Settings page shows.
type Status struct {
	Enabled bool   `json:"enabled"`
	Version string `json:"version"`
	// Install is "container" or "binary". Both switch the same way.
	Install string `json:"install"`
	Arch    string `json:"arch"`
	// Staged is true while a staged binary (not the installed one) runs.
	Staged       bool          `json:"staged"`
	CheckedAt    *time.Time    `json:"checked_at,omitempty"`
	CheckError   string        `json:"check_error,omitempty"`
	Releases     []ReleaseInfo `json:"releases"`
	Latest       *ReleaseInfo  `json:"latest,omitempty"`
	Available    bool          `json:"available"`
	Rollback     *VersionInfo  `json:"rollback,omitempty"`
	LastError    string        `json:"last_error,omitempty"`
	Pending      string        `json:"pending,omitempty"`
	CheckEvery   string        `json:"check_interval,omitempty"`
	HA           string        `json:"ha,omitempty"`
	NeedsStandby bool          `json:"needs_standby_upgraded"`
}

// Options build a Manager.
type Options struct {
	Config config.Upgrade
	// Version is the running version (main.version).
	Version string
	// ConfigPath is passed to the new binary's -check.
	ConfigPath string
	// Exe is the running executable.
	Exe string
	// Environ is the process environment.
	Environ []string
	// HA reports the elector's state. Nil means a single instance.
	HA func() plugin.ElectorStatus
	// Stop asks the controller to shut down as it does on SIGTERM: every
	// route withdrawn, the HA lease released. Required.
	Stop func()
	// StopDelay lets the API response go out before Stop runs.
	StopDelay time.Duration
	Log       *slog.Logger
	HTTP      *http.Client
	Now       func() time.Time
	// Trial runs a staged binary's start checks. Nil uses the binary's
	// -version and -check.
	Trial func(ctx context.Context, path, version string) error
	// Arch is the release asset architecture (default GOARCH).
	Arch string
	// Audit records a check that no signed-in user asked for.
	Audit func(action, detail string, err error)
}

// Manager checks for releases and prepares upgrades and rollbacks.
type Manager struct {
	opt   Options
	cl    *client
	store store

	mu        sync.Mutex
	busy      bool
	pending   *Target
	releases  []Release
	checkedAt time.Time
	checkErr  string
	lastErr   string
	baseVer   string
	basePath  string
	staged    bool
}

// New builds a Manager. Launched is whether this process was started from
// a staged binary; then the base comes from the state file.
func New(opt Options, launched bool) (*Manager, error) {
	if opt.Stop == nil {
		return nil, errors.New("upgrade: Stop is required")
	}
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Arch == "" {
		opt.Arch = runtime.GOARCH
	}
	if opt.HTTP == nil {
		opt.HTTP = &http.Client{Timeout: 5 * time.Minute}
	}
	if opt.StopDelay == 0 {
		opt.StopDelay = 500 * time.Millisecond
	}
	if opt.Trial == nil {
		opt.Trial = func(ctx context.Context, path, version string) error {
			return defaultTrial(ctx, path, version, opt.ConfigPath, opt.Environ)
		}
	}
	m := &Manager{opt: opt, store: store{dir: opt.Config.Dir},
		cl:      &client{api: opt.Config.APIURL, repo: opt.Config.Repo, http: opt.HTTP},
		baseVer: opt.Version, basePath: opt.Exe, staged: launched}
	if launched {
		st, err := m.store.load()
		if err != nil || st == nil {
			return nil, fmt.Errorf("upgrade: started from a staged binary but the state is unreadable: %v", err)
		}
		m.baseVer, m.basePath = st.BaseVersion, st.BasePath
	}
	return m, nil
}

// Install is "container" inside a container, else "binary".
func Install() string {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "container"
	}
	if os.Getenv("container") != "" {
		return "container"
	}
	return "binary"
}

// Confirm marks the running staged version as up. The controller calls it
// after the version has stayed up for a while.
func (m *Manager) Confirm() {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.store.load()
	if err != nil || st == nil || st.Confirmed {
		return
	}
	st.Confirmed, st.Attempts, st.LastError = true, 0, ""
	if err := m.store.save(st, m.opt.Now()); err != nil {
		m.opt.Log.Warn("upgrade: confirm not saved", "err", err)
	}
}

// Pending is the binary to start once the controller has shut down, if a
// switch was prepared.
func (m *Manager) Pending() (Target, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		return Target{}, false
	}
	return *m.pending, true
}

// Abort undoes a prepared switch whose shutdown did not finish cleanly:
// the state goes back to what ran before.
func (m *Manager) Abort(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		return
	}
	m.pending = nil
	st, err := m.store.load()
	if err != nil || st == nil {
		return
	}
	st.LastError = reason
	revert(st)
	_ = m.store.save(st, m.opt.Now())
}

// Status reports the running version, the last check, and the rollback
// target.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.statusLocked()
}

func (m *Manager) statusLocked() Status {
	s := Status{Enabled: true, Version: m.opt.Version, Install: Install(), Arch: m.opt.Arch, Staged: m.staged,
		CheckError: m.checkErr, LastError: m.lastErr, Releases: []ReleaseInfo{}}
	if m.opt.Config.CheckInterval > 0 {
		s.CheckEvery = m.opt.Config.CheckInterval.String()
	}
	if !m.checkedAt.IsZero() {
		t := m.checkedAt.UTC()
		s.CheckedAt = &t
	}
	for _, r := range m.releases {
		ri := ReleaseInfo{Release: r, Installable: r.Installable(m.opt.Arch), Current: Normalize(r.Tag) == Normalize(m.opt.Version)}
		if c, ok := Compare(r.Tag, m.opt.Version); ok {
			ri.Newer = c > 0
		} else {
			ri.Newer = !ri.Current
		}
		s.Releases = append(s.Releases, ri)
		if s.Latest == nil && ri.Installable && ri.Newer {
			cp := ri
			s.Latest = &cp
		}
	}
	s.Available = s.Latest != nil
	if st, err := m.store.load(); err == nil && st != nil {
		if st.LastError != "" {
			s.LastError = st.LastError
		}
		if !st.Previous.zero() {
			s.Rollback = &VersionInfo{Version: st.Previous.Version, Staged: st.Previous.Path != st.BasePath}
		}
	}
	if m.pending != nil {
		s.Pending = m.pending.Version
	}
	if m.opt.HA != nil {
		ha := m.opt.HA()
		s.HA = ha.Role
		s.NeedsStandby = ha.Role == plugin.RoleActive
	}
	return s
}

// Check reads the release list. It changes nothing on disk.
func (m *Manager) Check(ctx context.Context) (Status, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rels, err := m.cl.releases(ctx, m.opt.Config.AllowPrerelease)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkedAt = m.opt.Now()
	if err != nil {
		m.checkErr = err.Error()
		return m.statusLocked(), fmt.Errorf("%w: %v", ErrFetch, err)
	}
	m.checkErr = ""
	m.releases = rels
	return m.statusLocked(), nil
}

// Run checks on upgrade.check_interval until ctx ends. It only notifies:
// the result shows on the Settings page. It never upgrades.
func (m *Manager) Run(ctx context.Context) {
	every := m.opt.Config.CheckInterval
	if every <= 0 {
		return
	}
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		st, err := m.Check(ctx)
		if m.opt.Audit != nil {
			detail := "background check"
			if st.Latest != nil {
				detail += ": newer release " + st.Latest.Tag
			}
			m.opt.Audit("upgrade check", detail, err)
		}
		if st.Latest != nil {
			m.opt.Log.Info("a newer Packeteer release is available (nothing is upgraded automatically)", "running", m.opt.Version, "latest", st.Latest.Tag)
		}
		t.Reset(every)
	}
}

// haGuard enforces the pair's order: the standby first, then the active
// node. A standby only goes when an active node holds the lease; the
// active node needs the operator to say the standby already runs the
// target. The lease is what keeps the two from announcing at once: the
// shutdown that follows releases it only after the withdraw.
func (m *Manager) haGuard(req Request) error {
	if m.opt.HA == nil {
		return nil
	}
	ha := m.opt.HA()
	switch ha.Role {
	case plugin.RoleActive:
		if !req.StandbyUpgraded {
			return fmt.Errorf("%w: this node is active. Upgrade the standby first, then confirm that it runs the target version (standby_upgraded) so this node can hand over", ErrHA)
		}
	case plugin.RoleStandby:
		if ha.Holder == "" {
			return fmt.Errorf("%w: no node holds the lease; restarting this standby would leave no controller", ErrHA)
		}
	}
	return nil
}

func (m *Manager) begin(req Request) error {
	if !req.Confirm {
		return ErrNoConfirm
	}
	if err := m.haGuard(req); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.busy || m.pending != nil {
		return ErrBusy
	}
	m.busy = true
	return nil
}

func (m *Manager) end() {
	m.mu.Lock()
	m.busy = false
	m.mu.Unlock()
}

func (m *Manager) fail(err error) error {
	m.mu.Lock()
	m.lastErr = err.Error()
	m.mu.Unlock()
	return err
}

// Apply stages and verifies a release, records it as the version to run,
// and asks the controller to shut down. Until it returns without error
// nothing has changed.
func (m *Manager) Apply(ctx context.Context, req Request) (Result, error) {
	if err := m.begin(req); err != nil {
		return Result{}, err
	}
	defer m.end()
	res, err := m.apply(ctx, req)
	if err != nil {
		return Result{}, m.fail(err)
	}
	return res, nil
}

func (m *Manager) apply(ctx context.Context, req Request) (Result, error) {
	if !ValidTag(req.Tag) {
		return Result{}, ErrBadTag
	}
	version := Normalize(req.Tag)
	if version == Normalize(m.opt.Version) {
		return Result{}, ErrSame
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	rels, err := m.cl.releases(ctx, m.opt.Config.AllowPrerelease)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	var rel *Release
	for i := range rels {
		if rels[i].Tag == req.Tag {
			rel = &rels[i]
		}
	}
	if rel == nil {
		return Result{}, ErrNotFound
	}
	if !rel.Installable(m.opt.Arch) {
		return Result{}, ErrNotInstall
	}
	asset := AssetName(m.opt.Arch)

	// Verify the signed checksum file first, then the binary against it.
	sums, err := m.cl.get(ctx, rel.assets[SumsAsset], maxSmallAsset, "")
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	sig, err := m.cl.get(ctx, rel.assets[SigAsset], maxSmallAsset, "")
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	if err := VerifySignature(m.opt.Config.PublicKey, sums, sig); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrVerify, err)
	}
	want, err := checksumFor(sums, asset)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrVerify, err)
	}

	tmpDir := filepath.Join(m.store.dir, "tmp")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return Result{}, err
	}
	tmp, err := os.CreateTemp(tmpDir, "download-*")
	if err != nil {
		return Result{}, err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	if err := m.cl.stream(ctx, rel.assets[asset], maxBinary, io.MultiWriter(tmp, h)); err != nil {
		tmp.Close()
		return Result{}, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	if err := tmp.Close(); err != nil {
		return Result{}, err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return Result{}, fmt.Errorf("%w: %s checksum is %s, SHA256SUMS says %s", ErrVerify, asset, got, want)
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return Result{}, err
	}
	dest := m.store.versionPath(version)
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return Result{}, err
	}
	_, statErr := os.Stat(dest)
	existed := statErr == nil
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return Result{}, err
	}
	if err := m.opt.Trial(ctx, dest, version); err != nil {
		if !existed {
			_ = os.RemoveAll(filepath.Dir(dest))
		}
		return Result{}, fmt.Errorf("%w: %v", ErrTrial, err)
	}
	return m.switchTo(Entry{Version: version, Path: dest, SHA256: got}, "Upgrading")
}

// Rollback goes back to the previous version, after the same start check.
func (m *Manager) Rollback(ctx context.Context, req Request) (Result, error) {
	if err := m.begin(req); err != nil {
		return Result{}, err
	}
	defer m.end()
	res, err := m.rollback(ctx)
	if err != nil {
		return Result{}, m.fail(err)
	}
	return res, nil
}

func (m *Manager) rollback(ctx context.Context) (Result, error) {
	st, err := m.store.load()
	if err != nil {
		return Result{}, err
	}
	if st == nil || st.Previous.zero() {
		return Result{}, ErrNoPrevious
	}
	prev := st.Previous
	if prev.Path != st.BasePath {
		if sum, err := fileSHA256(prev.Path); err != nil || sum != prev.SHA256 {
			return Result{}, fmt.Errorf("%w: the previous version %s is missing or changed on disk", ErrNoPrevious, prev.Version)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := m.opt.Trial(ctx, prev.Path, prev.Version); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrTrial, err)
	}
	return m.switchTo(prev, "Rolling back")
}

// switchTo records e as the version to run, remembers what ran as the
// rollback target, and schedules the shutdown. The config is not touched.
func (m *Manager) switchTo(e Entry, verb string) (Result, error) {
	st, err := m.store.load()
	if err != nil {
		return Result{}, err
	}
	if st == nil {
		st = &State{BaseVersion: m.baseVer, BasePath: m.basePath,
			Active: Entry{Version: m.baseVer, Path: m.basePath}}
	}
	from := Normalize(m.opt.Version)
	st.Previous = st.Active
	if st.Previous.Path == "" {
		st.Previous = Entry{Version: m.baseVer, Path: m.basePath}
	}
	st.Active = e
	st.Attempts, st.Confirmed, st.LastError = 0, false, ""
	target := Target{Path: e.Path, Version: e.Version}
	if e.Path == st.BasePath {
		// The installed binary runs plain: no staged marker.
		st.Confirmed = true
		target.Env = without(m.opt.Environ, LaunchedEnv)
	} else {
		st.Attempts = 1
		target.Env = withLaunched(m.opt.Environ, e.Version)
	}
	if err := m.store.save(st, m.opt.Now()); err != nil {
		return Result{}, err
	}
	m.store.prune(st)
	m.mu.Lock()
	m.pending = &target
	m.lastErr = ""
	m.mu.Unlock()
	delay := m.opt.StopDelay
	go func() {
		time.Sleep(delay)
		m.opt.Stop()
	}()
	return Result{From: from, To: Normalize(e.Version), Message: fmt.Sprintf("%s %s to %s: Packeteer routes are withdrawn as on SIGTERM, then %s starts in the configured mode and learns the RIB again before it injects.", verb, from, Normalize(e.Version), Normalize(e.Version))}, nil
}

// defaultTrial runs the staged binary's -version, which must name the
// version, and -check against the mounted config. -check sends no probes
// and opens no BGP session.
func defaultTrial(ctx context.Context, path, version, configPath string, environ []string) error {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	env := withLaunched(environ, version)
	run := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Env = env
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return strings.TrimSpace(out.String()), err
	}
	out, err := run("-version")
	if err != nil {
		return fmt.Errorf("-version: %v: %s", err, tail(out))
	}
	if !strings.Contains(out, "packeteer "+Normalize(version)) {
		return fmt.Errorf("-version printed %q, want packeteer %s", tail(out), Normalize(version))
	}
	args := []string{"-check"}
	if configPath != "" {
		args = append(args, "-config", configPath)
	}
	if out, err := run(args...); err != nil {
		return fmt.Errorf("-check against the current config: %v: %s", err, tail(out))
	}
	return nil
}

func tail(s string) string {
	const n = 600
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}
