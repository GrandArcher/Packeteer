// Package exec implements the out-of-process "exec" plugin type for
// probers, target sources, and notifiers.
//
// Protocol (packeteer-exec/v1): for every call Packeteer starts the
// configured command, writes ONE JSON request to its stdin, closes stdin,
// and reads ONE JSON response from stdout. Stderr is logged. A non-zero
// exit status, a timeout, or {"error": "..."} is a failure. See
// docs/PLUGINS.md for the message shapes.
//
// Exec plugins can never be announcers.
package exec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "exec"

// Protocol is the protocol identifier sent with every request.
const Protocol = "packeteer-exec/v1"

// DefaultTimeout bounds a single plugin call.
const DefaultTimeout = 30 * time.Second

const maxOutput = 1 << 20 // 1 MiB of stdout/stderr per call

func init() {
	plugin.Probers.Register(TypeName, func(c plugin.Config, e plugin.Env) (plugin.Prober, error) {
		r, err := newRunner(plugin.KindProber, c, e)
		if err != nil {
			return nil, err
		}
		return &Prober{r: r}, nil
	})
	plugin.Sources.Register(TypeName, func(c plugin.Config, e plugin.Env) (plugin.TargetSource, error) {
		r, err := newRunner(plugin.KindSource, c, e)
		if err != nil {
			return nil, err
		}
		return &Source{r: r}, nil
	})
	plugin.Notifiers.Register(TypeName, func(c plugin.Config, e plugin.Env) (plugin.Notifier, error) {
		r, err := newRunner(plugin.KindNotifier, c, e)
		if err != nil {
			return nil, err
		}
		return &Notifier{r: r}, nil
	})
}

// Config is the exec plugin's config block.
type Config struct {
	// Command is an absolute path, or a path relative to the plugin dir.
	Command string        `yaml:"command"`
	Args    []string      `yaml:"args"`
	Timeout time.Duration `yaml:"timeout"`
	// Env is passed to the process; values may reference ${VAR} from
	// Packeteer's environment. The rest of Packeteer's environment is not
	// inherited (only PATH).
	Env map[string]string `yaml:"env"`
	// Config is forwarded verbatim to the plugin in every request.
	Config any `yaml:"config"`
}

type request struct {
	Protocol string `json:"protocol"`
	Kind     string `json:"kind"`
	Method   string `json:"method"`
	Name     string `json:"name"`
	Config   any    `json:"config,omitempty"`
	Params   any    `json:"params,omitempty"`
}

type response struct {
	Result json.RawMessage `json:"result"`
	Error  string          `json:"error"`
}

type runner struct {
	kind    plugin.Kind
	name    string
	path    string
	args    []string
	env     []string
	timeout time.Duration
	config  any
	log     *slog.Logger
}

// ResolveCommand maps a configured command to an executable path. Relative
// paths must stay inside dir.
func ResolveCommand(dir, cmd string) (string, error) {
	if cmd == "" {
		return "", errors.New("command is required")
	}
	if filepath.IsAbs(cmd) {
		return filepath.Clean(cmd), nil
	}
	clean := filepath.Clean(cmd)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("command %q escapes the plugin dir", cmd)
	}
	if dir == "" {
		return "", fmt.Errorf("command %q is relative but no plugin dir is set", cmd)
	}
	return filepath.Join(dir, clean), nil
}

func newRunner(kind plugin.Kind, c plugin.Config, e plugin.Env) (*runner, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	path, err := ResolveCommand(e.PluginDir, cfg.Command)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("command: %w", err)
	}
	if st.IsDir() || st.Mode()&0o111 == 0 {
		return nil, fmt.Errorf("command %s is not an executable file", path)
	}
	if cfg.Timeout < 0 {
		return nil, fmt.Errorf("timeout %s must not be negative", cfg.Timeout)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	getenv := e.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	env := []string{"PATH=" + firstNonEmpty(getenv("PATH"), "/usr/local/bin:/usr/bin:/bin"), "PACKETEER_PLUGIN_KIND=" + string(kind)}
	for k, v := range cfg.Env {
		if k == "" || strings.ContainsAny(k, "=\x00") {
			return nil, fmt.Errorf("env: invalid variable name %q", k)
		}
		env = append(env, k+"="+os.Expand(v, getenv))
	}
	logger := e.Logger
	if logger == nil {
		logger = slog.Default()
	}
	r := &runner{kind: kind, name: e.Name, path: path, args: cfg.Args, env: env,
		timeout: cfg.Timeout, config: cfg.Config, log: logger}

	// Init handshake: lets the plugin validate its own config at load time.
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	if err := r.call(ctx, "init", nil, nil); err != nil {
		return nil, fmt.Errorf("init: %w", err)
	}
	return r, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

type limitedBuffer struct {
	bytes.Buffer
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := maxOutput - b.Len(); len(p) > room {
		b.overflow = true
		if room > 0 {
			b.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// call runs one request/response exchange and decodes the result into out.
func (r *runner) call(ctx context.Context, method string, params, out any) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	in, err := json.Marshal(request{Protocol: Protocol, Kind: string(r.kind), Method: method,
		Name: r.name, Config: r.config, Params: params})
	if err != nil {
		return err
	}
	cmd := osexec.CommandContext(ctx, r.path, r.args...)
	cmd.Env = r.env
	cmd.Stdin = bytes.NewReader(in)
	var stdout, stderr limitedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = time.Second
	runErr := cmd.Run()
	if s := strings.TrimSpace(stderr.String()); s != "" {
		r.log.Debug("exec plugin stderr", "method", method, "stderr", s)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("%s: timed out after %s", method, r.timeout)
	}
	if runErr != nil {
		return fmt.Errorf("%s: %v: %s", method, runErr, tail(stderr.String()))
	}
	if stdout.overflow {
		return fmt.Errorf("%s: response larger than %d bytes", method, maxOutput)
	}
	var resp response
	dec := json.NewDecoder(&stdout)
	if err := dec.Decode(&resp); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%s: plugin wrote no response", method)
		}
		return fmt.Errorf("%s: invalid JSON response: %w", method, err)
	}
	if resp.Error != "" {
		return fmt.Errorf("%s: plugin error: %s", method, resp.Error)
	}
	if out != nil {
		if len(resp.Result) == 0 || string(resp.Result) == "null" {
			return fmt.Errorf("%s: response has no result", method)
		}
		if err := json.Unmarshal(resp.Result, out); err != nil {
			return fmt.Errorf("%s: bad result: %w", method, err)
		}
	}
	return nil
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 512 {
		s = "..." + s[len(s)-512:]
	}
	return s
}

// ---- Prober ----

// Prober is an exec-backed plugin.Prober.
type Prober struct {
	plugin.Base
	r *runner
}

type probeParams struct {
	Provider  string `json:"provider"`
	Source    string `json:"source"`
	Target    string `json:"target"`
	Count     int    `json:"count"`
	TimeoutMs int64  `json:"timeout_ms"`
}

type probeResult struct {
	Sent   int       `json:"sent"`
	RTTsMs []float64 `json:"rtts_ms"`
}

// Probe implements plugin.Prober.
func (p *Prober) Probe(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	var res probeResult
	err := p.r.call(ctx, "probe", probeParams{Provider: req.Provider, Source: req.Source.String(),
		Target: req.Target.String(), Count: req.Count, TimeoutMs: req.Timeout.Milliseconds()}, &res)
	if err != nil {
		return plugin.ProbeResult{}, err
	}
	if res.Sent < 0 || len(res.RTTsMs) > res.Sent {
		return plugin.ProbeResult{}, fmt.Errorf("probe: inconsistent result: sent=%d replies=%d", res.Sent, len(res.RTTsMs))
	}
	out := plugin.ProbeResult{Sent: res.Sent}
	for _, ms := range res.RTTsMs {
		if ms < 0 {
			return plugin.ProbeResult{}, fmt.Errorf("probe: negative rtt %v", ms)
		}
		out.RTTs = append(out.RTTs, time.Duration(ms*float64(time.Millisecond)))
	}
	return out, nil
}

// ---- Target source ----

// Source is an exec-backed plugin.TargetSource.
type Source struct {
	plugin.Base
	r *runner
}

type targetsResult struct {
	Targets []struct {
		Prefix string  `json:"prefix"`
		Host   string  `json:"host"`
		Weight float64 `json:"weight"`
	} `json:"targets"`
}

// Targets implements plugin.TargetSource.
func (s *Source) Targets(ctx context.Context) ([]plugin.Target, error) {
	var res targetsResult
	if err := s.r.call(ctx, "targets", nil, &res); err != nil {
		return nil, err
	}
	out := make([]plugin.Target, 0, len(res.Targets))
	for i, t := range res.Targets {
		p, err := netip.ParsePrefix(t.Prefix)
		if err != nil {
			return nil, fmt.Errorf("targets[%d]: bad prefix %q", i, t.Prefix)
		}
		tg := plugin.Target{Prefix: p.Masked(), Weight: t.Weight}
		if t.Host != "" {
			h, err := netip.ParseAddr(t.Host)
			if err != nil || !p.Contains(h) {
				return nil, fmt.Errorf("targets[%d]: host %q is not an address inside %s", i, t.Host, p)
			}
			tg.Host = h
		}
		out = append(out, tg)
	}
	return out, nil
}

// ---- Notifier ----

// Notifier is an exec-backed plugin.Notifier.
type Notifier struct {
	plugin.Base
	r *runner
}

// Notify implements plugin.Notifier.
func (n *Notifier) Notify(ctx context.Context, e plugin.Event) error {
	return n.r.call(ctx, "notify", e, nil)
}
