// Package agent is the packeteer-agent client (#230): a probe-only process
// that an operator runs inside its own network. It has no BGP, no
// injection, no UI, and no listener. It calls the controller over mutual
// TLS, takes probe tasks, runs them with a normal prober plugin from the
// source address and tag it declares for each provider, and posts the raw
// replies back.
//
// An agent holds no state worth keeping: a task that is not answered
// within its own timeout is dropped, and with the controller gone the
// agent only retries its poll. Nothing it does can reach routing.
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/agentwire"
	"github.com/GrandArcher/Packeteer/internal/sockmark"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Defaults and limits.
const (
	DefaultMaxConcurrent = 8
	maxConcurrentLimit   = 256
	// pollSlack is added to the longest poll the controller may hold
	// (agentwire.MaxPollWait) for the bound on one poll. A connection that
	// goes silent is dropped after it and the poll is retried.
	pollSlack = 10 * time.Second
	minRetry  = time.Second
	maxRetry  = 15 * time.Second
)

// Config is the agent's config file.
type Config struct {
	// ControllerURL is the controller's https base URL for agents.
	ControllerURL string `yaml:"controller_url"`
	// ServerName overrides the name checked on the controller's
	// certificate (default: the host in controller_url).
	ServerName string `yaml:"server_name"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	CAFile     string `yaml:"ca_file"`
	// Site names where this agent runs. The controller matches it with
	// providers[].site.
	Site string `yaml:"site"`
	// Providers are the egress paths this agent can test.
	Providers []Provider `yaml:"providers"`
	// Prober is the prober plugin that takes the measurements (default
	// icmp).
	Prober ProberSpec `yaml:"prober"`
	// MaxConcurrent bounds the probes running at once (default 8).
	MaxConcurrent int `yaml:"max_concurrent"`
}

// Provider is one egress path as seen from the agent. Name must match a
// provider in the controller's config.
type Provider struct {
	Name     string `yaml:"name"`
	SourceIP string `yaml:"source_ip"`
	FwMark   uint32 `yaml:"fwmark"`
	DSCP     int    `yaml:"dscp"`
}

// ProberSpec selects the prober plugin.
type ProberSpec struct {
	Type   string    `yaml:"type"`
	Config yaml.Node `yaml:"config"`
}

type provider struct {
	source netip.Addr
	mark   uint32
	dscp   uint8
}

// Agent is a configured probe agent.
type Agent struct {
	cfg       Config
	log       *slog.Logger
	prober    plugin.Prober
	providers map[string]provider
	names     []string
	pollURL   string
	resultURL string
	client    *http.Client
	sem       chan struct{} // one slot per running probe
	// pollTimeout bounds one poll call.
	pollTimeout time.Duration
}

// Load reads and strictly decodes an agent config file.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// New validates cfg and builds the prober and the TLS client. It does not
// touch the network. A nil prober builds the configured plugin.
func New(cfg Config, prober plugin.Prober, log *slog.Logger) (*Agent, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = DefaultMaxConcurrent
	}
	if cfg.MaxConcurrent < 1 || cfg.MaxConcurrent > maxConcurrentLimit {
		return nil, fmt.Errorf("max_concurrent %d must be between 1 and %d", cfg.MaxConcurrent, maxConcurrentLimit)
	}
	if !agentwire.NameRE.MatchString(cfg.Site) {
		return nil, fmt.Errorf("site %q must be 1-64 characters of letters, digits, '_', '.' or '-'", cfg.Site)
	}
	u, err := url.Parse(cfg.ControllerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return nil, fmt.Errorf("controller_url %q must be https://host:port", cfg.ControllerURL)
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" || cfg.CAFile == "" {
		return nil, errors.New("cert_file, key_file, and ca_file are required (mutual TLS)")
	}
	a := &Agent{cfg: cfg, log: log, pollTimeout: agentwire.MaxPollWait + pollSlack, providers: map[string]provider{}, sem: make(chan struct{}, cfg.MaxConcurrent),
		pollURL: "https://" + u.Host + agentwire.PollPath, resultURL: "https://" + u.Host + agentwire.ResultsPath}
	if len(cfg.Providers) == 0 || len(cfg.Providers) > agentwire.MaxProviders {
		return nil, fmt.Errorf("providers: list between 1 and %d", agentwire.MaxProviders)
	}
	for i, p := range cfg.Providers {
		if !agentwire.NameRE.MatchString(p.Name) {
			return nil, fmt.Errorf("providers[%d]: name %q must be 1-64 characters of letters, digits, '_', '.' or '-'", i, p.Name)
		}
		if _, dup := a.providers[p.Name]; dup {
			return nil, fmt.Errorf("providers[%d]: duplicate name %q", i, p.Name)
		}
		src, err := netip.ParseAddr(p.SourceIP)
		if err != nil {
			return nil, fmt.Errorf("providers[%d] (%s): source_ip %q is not an IP address", i, p.Name, p.SourceIP)
		}
		if p.DSCP < 0 || p.DSCP > sockmark.MaxDSCP {
			return nil, fmt.Errorf("providers[%d] (%s): dscp %d must be between 0 and %d", i, p.Name, p.DSCP, sockmark.MaxDSCP)
		}
		a.providers[p.Name] = provider{source: src, mark: p.FwMark, dscp: uint8(p.DSCP)}
		a.names = append(a.names, p.Name)
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("cert_file/key_file: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("ca_file %s: no PEM certificates", cfg.CAFile)
	}
	a.client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: cfg.ServerName}}}
	if prober == nil {
		typ := cfg.Prober.Type
		if typ == "" {
			typ = "icmp"
		}
		if prober, err = plugin.Probers.New(typ, plugin.NewConfig(&cfg.Prober.Config), plugin.Env{Name: typ, Logger: log}); err != nil {
			return nil, fmt.Errorf("prober %s: %w", typ, err)
		}
	}
	a.prober = prober
	return a, nil
}

// Run polls the controller until ctx ends. A controller that is down or
// refuses the agent is retried with a growing pause; no task runs without
// one from the controller.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.prober.Start(ctx); err != nil {
		return fmt.Errorf("prober: %w", err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.prober.Stop(sctx)
	}()
	retry, failing := minRetry, false
	for ctx.Err() == nil {
		free := min(cap(a.sem)-len(a.sem), agentwire.MaxTasksPerPoll)
		if free == 0 {
			sleep(ctx, 50*time.Millisecond)
			continue
		}
		tasks, err := a.poll(ctx, free)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			if !failing {
				a.log.Warn("controller not reachable; retrying", "err", err)
				failing = true
			}
			sleep(ctx, retry)
			retry = min(retry*2, maxRetry)
			continue
		}
		if failing {
			a.log.Info("controller reachable again")
			failing = false
		}
		retry = minRetry
		for _, t := range tasks {
			a.sem <- struct{}{}
			go func() {
				defer func() { <-a.sem }()
				a.run(ctx, t)
			}()
		}
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func (a *Agent) poll(ctx context.Context, free int) ([]agentwire.Task, error) {
	var resp agentwire.PollResponse
	req := agentwire.PollRequest{Site: a.cfg.Site, Providers: a.names, Free: free}
	if err := a.post(ctx, a.pollURL, req, &resp, a.pollTimeout); err != nil {
		return nil, err
	}
	if len(resp.Tasks) > free {
		return nil, fmt.Errorf("controller sent %d tasks for %d free slots", len(resp.Tasks), free)
	}
	return resp.Tasks, nil
}

// post sends v as JSON and decodes the answer into out (nil: expect none).
func (a *Agent) post(ctx context.Context, u string, v, out any, timeout time.Duration) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("controller answered %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, agentwire.MaxBody)).Decode(out)
}

// run measures one task and posts the answer. An answer that cannot be
// posted is dropped: the controller has given up on the task by then.
func (a *Agent) run(ctx context.Context, t agentwire.Task) {
	res := agentwire.Result{ID: t.ID}
	req, err := a.request(t)
	if err == nil {
		pctx, cancel := context.WithTimeout(ctx, time.Duration(t.Count)*req.Timeout+time.Second)
		var raw plugin.ProbeResult
		raw, err = a.prober.Probe(pctx, req)
		cancel()
		res.Sent = raw.Sent
		for _, d := range raw.RTTs {
			res.RTTsNS = append(res.RTTsNS, int64(d))
		}
	}
	if err != nil {
		res.Error, res.SourceUnavailable = err.Error(), errors.Is(err, plugin.ErrSourceUnavailable)
	}
	if err := a.post(ctx, a.resultURL, agentwire.ResultsRequest{Results: []agentwire.Result{res}}, nil, pollSlack); err != nil && ctx.Err() == nil {
		a.log.Warn("result not delivered", "task", t.ID, "provider", t.Provider, "err", err)
	}
}

// request turns a task into a probe request from the declared provider.
// A task for a provider the agent did not declare, or outside the limits,
// is refused.
func (a *Agent) request(t agentwire.Task) (plugin.ProbeRequest, error) {
	p, ok := a.providers[t.Provider]
	if !ok {
		return plugin.ProbeRequest{}, fmt.Errorf("provider %q is not declared on this agent", t.Provider)
	}
	target, err := netip.ParseAddr(t.Target)
	if err != nil {
		return plugin.ProbeRequest{}, fmt.Errorf("target %q is not an IP address", t.Target)
	}
	if target.Is4() != p.source.Is4() {
		return plugin.ProbeRequest{}, fmt.Errorf("target %s is not in the address family of provider %s source %s", target, t.Provider, p.source)
	}
	if t.Count < 1 || t.Count > agentwire.MaxCount || t.TimeoutMS < 1 || t.TimeoutMS > agentwire.MaxTimeoutMS {
		return plugin.ProbeRequest{}, fmt.Errorf("count %d or timeout %dms outside the limits", t.Count, t.TimeoutMS)
	}
	return plugin.ProbeRequest{Provider: t.Provider, Source: p.source, Target: target, Count: t.Count,
		Timeout: time.Duration(t.TimeoutMS) * time.Millisecond, Mark: p.mark, DSCP: p.dscp}, nil
}
