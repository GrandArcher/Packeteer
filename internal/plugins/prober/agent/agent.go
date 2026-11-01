// Package agent is the controller side of the distributed probe agents
// (#230). It is a prober: a probe for a provider that has a site is handed
// to a packeteer-agent at that site, which measures from where the
// provider's traffic leaves and sends the replies back. The agents call
// this server over mutual TLS, so a remote site needs no inbound port.
//
// The plugin only measures. It never announces, never decides, and never
// lets an agent choose what to probe: tasks come from the engine. An agent
// that stops reporting, or whose certificate is revoked, is not used, and
// when no agent at a site is usable the provider fails closed like a
// probe source that cannot be bound.
package agent

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/GrandArcher/Packeteer/internal/agentwire"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "agent"

// Defaults and limits.
const (
	DefaultPollWait = 5 * time.Second
	DefaultMaxPPS   = 100
	maxAgents       = 256
	maxPPSLimit     = 100000
	// reapEvery is how often agent freshness and the CRL file are checked.
	reapEvery = 250 * time.Millisecond
)

func init() { plugin.Probers.Register(TypeName, New) }

// Config is the agent prober's config block.
type Config struct {
	// Listen is the address agents connect to.
	Listen   string `yaml:"listen"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
	// CRLFile, when set, is a PEM certificate revocation list signed by
	// the CA. It is read at start and again whenever the file changes. An
	// agent whose certificate is listed is refused and not used.
	CRLFile string `yaml:"crl_file"`
	// Agents lists the agents that may connect. A certificate whose CN or
	// DNS SAN is not listed is refused, so removing an entry and
	// restarting revokes that agent too.
	Agents []Agent `yaml:"agents"`
	// PollWait is how long the controller holds an agent's poll when it
	// has no work (default 5s). It is the agent's heartbeat.
	PollWait time.Duration `yaml:"poll_wait"`
	// MaxAge is how long an agent stays usable after it last called
	// (default 3x poll_wait). Past it the agent is stale and not used.
	MaxAge time.Duration `yaml:"max_age"`
}

// Agent is one allowed probe agent.
type Agent struct {
	// Name is the certificate name (CN or DNS SAN) the agent presents.
	Name string `yaml:"name"`
	// MaxPPS caps the probe packets per second sent to this agent
	// (default 100).
	MaxPPS int `yaml:"max_pps"`
}

type outcome struct {
	res plugin.ProbeResult
	err error
}

// task is one probe handed to an agent.
type task struct {
	wire  agentwire.Task
	site  string
	agent string
	done  chan outcome // buffered: the resolver never blocks
}

type agentState struct {
	spec      Agent
	lim       *rate.Limiter
	site      string
	providers map[string]bool
	issuer    string // identifies the certificate last seen, for revocation
	serial    string
	lastSeen  time.Time
	up        bool // last logged state
	queue     []*task
	inflight  map[uint64]*task
	served    uint64
	wake      chan struct{} // poll wake-up, buffered 1
}

// Prober hands probes to the connected agents.
type Prober struct {
	cfg  Config
	log  *slog.Logger
	cert tls.Certificate
	pool *x509.CertPool
	cas  []*x509.Certificate
	now  func() time.Time

	crl     atomic.Pointer[map[string]bool]
	crlStat atomic.Pointer[fileStamp]

	mu     sync.Mutex
	agents map[string]*agentState
	nextID uint64

	srv    *http.Server
	ln     net.Listener
	cancel context.CancelFunc
	stop   chan struct{}
	wg     sync.WaitGroup
}

// Remote marks the prober as one that serves provider sites.
func (*Prober) Remote() {}

// New is the plugin factory. It reads the certificate files and the CRL
// but does not touch the network.
func New(c plugin.Config, env plugin.Env) (plugin.Prober, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.PollWait == 0 {
		cfg.PollWait = DefaultPollWait
	}
	if cfg.PollWait < 100*time.Millisecond || cfg.PollWait > agentwire.MaxPollWait {
		return nil, fmt.Errorf("poll_wait %s must be between 100ms and 30s", cfg.PollWait)
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 3 * cfg.PollWait
	}
	if cfg.MaxAge <= cfg.PollWait || cfg.MaxAge > 10*time.Minute {
		return nil, fmt.Errorf("max_age %s must be longer than poll_wait and at most 10m", cfg.MaxAge)
	}
	if _, port, err := net.SplitHostPort(cfg.Listen); err != nil || port == "" {
		return nil, fmt.Errorf("listen %q must be host:port", cfg.Listen)
	}
	if len(cfg.Agents) == 0 || len(cfg.Agents) > maxAgents {
		return nil, fmt.Errorf("agents: list between 1 and %d agents", maxAgents)
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" || cfg.CAFile == "" {
		return nil, errors.New("cert_file, key_file, and ca_file are required (mutual TLS)")
	}
	p := &Prober{cfg: cfg, log: env.Logger, now: time.Now, agents: map[string]*agentState{}, stop: make(chan struct{})}
	if p.log == nil {
		p.log = slog.Default()
	}
	for i, a := range cfg.Agents {
		if !agentwire.NameRE.MatchString(a.Name) {
			return nil, fmt.Errorf("agents[%d]: name %q must be 1-64 characters of letters, digits, '_', '.' or '-'", i, a.Name)
		}
		if p.agents[a.Name] != nil {
			return nil, fmt.Errorf("agents[%d]: duplicate name %q", i, a.Name)
		}
		if a.MaxPPS == 0 {
			a.MaxPPS = DefaultMaxPPS
		}
		if a.MaxPPS < 1 || a.MaxPPS > maxPPSLimit {
			return nil, fmt.Errorf("agents[%d] (%s): max_pps %d must be between 1 and %d", i, a.Name, a.MaxPPS, maxPPSLimit)
		}
		p.agents[a.Name] = &agentState{spec: a, inflight: map[uint64]*task{}, wake: make(chan struct{}, 1),
			// A burst of agentwire.MaxCount lets any one task through.
			lim: rate.NewLimiter(rate.Limit(a.MaxPPS), max(a.MaxPPS, agentwire.MaxCount))}
	}
	var err error
	if p.cert, err = tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile); err != nil {
		return nil, fmt.Errorf("cert_file/key_file: %w", err)
	}
	if p.pool, p.cas, err = loadCAs(cfg.CAFile); err != nil {
		return nil, err
	}
	if cfg.CRLFile != "" {
		if err := p.reloadCRL(); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// Start listens for agents. It does not block.
func (p *Prober) Start(context.Context) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	ln, err := net.Listen("tcp", p.cfg.Listen)
	if err != nil {
		cancel()
		return fmt.Errorf("agent listen %s: %w", p.cfg.Listen, err)
	}
	p.ln = ln
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+agentwire.PollPath, p.servePoll)
	mux.HandleFunc("POST "+agentwire.ResultsPath, p.serveResults)
	p.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      p.cfg.PollWait + 15*time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(p.log.Handler(), slog.LevelDebug),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{p.cert},
			ClientCAs:    p.pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		},
	}
	tln := tls.NewListener(ln, p.srv.TLSConfig)
	p.wg.Add(2)
	go func() {
		defer p.wg.Done()
		if err := p.srv.Serve(tln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			p.log.Error("probe agent server", "err", err)
		}
	}()
	go func() {
		defer p.wg.Done()
		p.reap(ctx)
	}()
	p.log.Info("probe agents listening (mutual TLS)", "addr", ln.Addr().String(), "agents", len(p.agents))
	return nil
}

// Addr is the bound listen address (tests use port 0). Nil before Start.
func (p *Prober) Addr() net.Addr {
	if p.ln == nil {
		return nil
	}
	return p.ln.Addr()
}

// Stop closes the server and fails every task still waiting.
func (p *Prober) Stop(ctx context.Context) error {
	if p.cancel == nil {
		return nil
	}
	p.cancel()
	close(p.stop)
	p.mu.Lock()
	for _, a := range p.agents {
		p.failLocked(a, errors.New("controller stopping"))
	}
	p.mu.Unlock()
	err := p.srv.Shutdown(ctx)
	if err != nil {
		_ = p.srv.Close()
	}
	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	return err
}

// freshLocked reports whether the agent may be given work: it called
// within max_age and its certificate is not revoked.
func (p *Prober) freshLocked(a *agentState, now time.Time) bool {
	return !a.lastSeen.IsZero() && now.Sub(a.lastSeen) <= p.cfg.MaxAge && !p.revoked(a.issuer, a.serial)
}

// candidate is an agent that can take one probe.
type candidate struct {
	a     *agentState
	res   *rate.Reservation
	delay time.Duration
}

// Probe hands the request to one usable agent at the provider's site and
// waits for its answer. The agent with the earliest rate-limit slot wins,
// then the one with the least work queued, then the one that served the
// fewest probes, so the load spreads. No usable agent fails the provider
// closed (plugin.ErrSourceUnavailable). A lost agent is a plain error: the
// round keeps the provider's previous result, which goes stale on its own.
func (p *Prober) Probe(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	if req.Site == "" {
		return plugin.ProbeResult{}, errors.New("agent prober serves only providers with a site")
	}
	if req.Count < 1 || req.Count > agentwire.MaxCount {
		return plugin.ProbeResult{}, fmt.Errorf("count %d must be between 1 and %d", req.Count, agentwire.MaxCount)
	}
	if req.Timeout <= 0 || req.Timeout.Milliseconds() > agentwire.MaxTimeoutMS {
		return plugin.ProbeResult{}, fmt.Errorf("timeout %s must be between 1ms and %dms", req.Timeout, agentwire.MaxTimeoutMS)
	}
	t, delay, release, err := p.reserve(ctx, req)
	if err != nil {
		return plugin.ProbeResult{}, err
	}
	if delay > 0 {
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			release()
			return plugin.ProbeResult{}, ctx.Err()
		}
		p.mu.Lock()
		a := p.agents[t.agent]
		if !p.freshLocked(a, p.now()) {
			p.mu.Unlock()
			release()
			return plugin.ProbeResult{}, fmt.Errorf("agent %s went away", t.agent)
		}
		p.enqueueLocked(a, t)
		p.mu.Unlock()
	}
	select {
	case o := <-t.done:
		return o.res, o.err
	case <-ctx.Done():
		p.mu.Lock()
		p.dropLocked(p.agents[t.agent], t)
		p.mu.Unlock()
		return plugin.ProbeResult{}, ctx.Err()
	}
}

// reserve picks the agent and takes its rate-limit slot. With no wait the
// task is already queued; otherwise the caller queues it after delay.
// release returns an unused slot.
func (p *Prober) reserve(ctx context.Context, req plugin.ProbeRequest) (t *task, delay time.Duration, release func(), err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	var cands []candidate
	for _, a := range p.agents {
		if a.site != req.Site || !a.providers[req.Provider] || !p.freshLocked(a, now) {
			continue
		}
		r := a.lim.ReserveN(now, req.Count)
		if !r.OK() {
			continue
		}
		cands = append(cands, candidate{a: a, res: r, delay: r.DelayFrom(now)})
	}
	if len(cands) == 0 {
		return nil, 0, nil, fmt.Errorf("%w: no usable probe agent at site %s for provider %s", plugin.ErrSourceUnavailable, req.Site, req.Provider)
	}
	slices.SortFunc(cands, func(x, y candidate) int {
		return cmp.Or(cmp.Compare(x.delay, y.delay),
			cmp.Compare(len(x.a.queue)+len(x.a.inflight), len(y.a.queue)+len(y.a.inflight)),
			cmp.Compare(x.a.served, y.a.served),
			cmp.Compare(x.a.spec.Name, y.a.spec.Name))
	})
	for _, c := range cands[1:] {
		c.res.CancelAt(now)
	}
	best := cands[0]
	release = func() { best.res.CancelAt(p.now()) }
	if dl, ok := ctx.Deadline(); ok && now.Add(best.delay).After(dl) {
		release()
		return nil, 0, nil, fmt.Errorf("probe agents at site %s are at their rate limit", req.Site)
	}
	p.nextID++
	t = &task{site: best.a.site, agent: best.a.spec.Name, done: make(chan outcome, 1), wire: agentwire.Task{
		ID: p.nextID, Provider: req.Provider, Target: req.Target.String(), Count: req.Count, TimeoutMS: req.Timeout.Milliseconds()}}
	best.a.served++
	if best.delay == 0 {
		p.enqueueLocked(best.a, t)
	}
	return t, best.delay, release, nil
}

func (p *Prober) enqueueLocked(a *agentState, t *task) {
	a.queue = append(a.queue, t)
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

// dropLocked forgets a task whose caller gave up. A late answer for it is
// ignored.
func (p *Prober) dropLocked(a *agentState, t *task) {
	a.queue = slices.DeleteFunc(a.queue, func(q *task) bool { return q == t })
	delete(a.inflight, t.wire.ID)
}

// failLocked answers every task of the agent with err.
func (p *Prober) failLocked(a *agentState, err error) {
	for _, t := range a.queue {
		t.done <- outcome{err: err}
	}
	for _, t := range a.inflight {
		t.done <- outcome{err: err}
	}
	a.queue, a.inflight = nil, map[uint64]*task{}
}

// reap marks agents stale, fails their tasks, and re-reads a changed CRL.
func (p *Prober) reap(ctx context.Context) {
	tick := time.NewTicker(reapEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if p.cfg.CRLFile != "" && p.crlChanged() {
			if err := p.reloadCRL(); err != nil {
				p.log.Error("probe agent CRL not reloaded; the previous list stays", "err", err)
			}
		}
		p.mu.Lock()
		now := p.now()
		for _, a := range p.agents {
			if !a.up || p.freshLocked(a, now) {
				continue
			}
			a.up = false
			p.failLocked(a, fmt.Errorf("agent %s is stale", a.spec.Name))
			p.log.Warn("probe agent stale; its data is not used", "agent", a.spec.Name, "site", a.site)
		}
		p.mu.Unlock()
	}
}
