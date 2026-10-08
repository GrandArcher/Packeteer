// Package fixed is a prober that returns configured results and never sends
// a packet. It exists so labs and tests can drive the decision engine
// deterministically. Do not use it to measure a real network.
//
// A file, when set, is re-read on every Probe call, so a lab can flip results
// without restarting Packeteer.
package fixed

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"net/netip"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "fixed"

// maxFile is how large a results file may be.
const maxFile = 1 << 20

func init() { plugin.Probers.Register(TypeName, New) }

// Config is the fixed prober's config block.
type Config struct {
	// File is re-read on every probe. Its contents use this same schema
	// (sent, rtt_ms, paths) without the file field.
	File  string     `yaml:"file"`
	Sent  int        `yaml:"sent"`
	RTTMs float64    `yaml:"rtt_ms"`
	Paths []PathSpec `yaml:"paths"`
}

// PathSpec is one fixed result. provider is required. target and count,
// when set, narrow the match: the first most-specific path wins.
type PathSpec struct {
	Provider   string    `yaml:"provider"`
	Target     string    `yaml:"target"`
	Count      int       `yaml:"count"`
	Sent       int       `yaml:"sent"`
	RTTMs      float64   `yaml:"rtt_ms"`
	RTTsMs     []float64 `yaml:"rtts_ms"`
	LossPct    float64   `yaml:"loss_pct"`
	SourceDown bool      `yaml:"source_down"`
}

// Prober returns configured probe results.
type Prober struct {
	plugin.Base
	file  string
	sent  int
	rttMs float64
	paths []PathSpec
}

// New is the plugin factory.
func New(c plugin.Config, _ plugin.Env) (plugin.Prober, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	p := &Prober{file: cfg.File, sent: cfg.Sent, rttMs: cfg.RTTMs}
	if err := p.setPaths(cfg.Paths); err != nil {
		return nil, err
	}
	if cfg.Sent < 0 {
		return nil, fmt.Errorf("sent %d must not be negative", cfg.Sent)
	}
	if cfg.RTTMs < 0 {
		return nil, fmt.Errorf("rtt_ms %v must not be negative", cfg.RTTMs)
	}
	if cfg.File != "" {
		snap, err := p.readFile()
		if err != nil {
			return nil, err
		}
		tmp := &Prober{}
		if err := tmp.setPaths(snap.Paths); err != nil {
			return nil, fmt.Errorf("fixed prober: %s: %w", cfg.File, err)
		}
	} else if len(cfg.Paths) == 0 && cfg.Sent == 0 && cfg.RTTMs == 0 {
		return nil, fmt.Errorf("fixed prober: set paths, sent/rtt_ms, or file")
	}
	return p, nil
}

func (p *Prober) setPaths(paths []PathSpec) error {
	seen := map[string]bool{}
	out := make([]PathSpec, len(paths))
	for i, s := range paths {
		if s.Provider == "" {
			return fmt.Errorf("paths[%d]: provider is required", i)
		}
		if s.Target != "" {
			a, err := netip.ParseAddr(s.Target)
			if err != nil {
				return fmt.Errorf("paths[%d]: target %q is not an IP address", i, s.Target)
			}
			s.Target = a.String()
		}
		if s.Count < 0 || s.Count > 1000 {
			return fmt.Errorf("paths[%d]: count %d must be between 0 and 1000", i, s.Count)
		}
		if s.Sent < 0 {
			return fmt.Errorf("paths[%d]: sent %d must not be negative", i, s.Sent)
		}
		if s.RTTMs < 0 {
			return fmt.Errorf("paths[%d]: rtt_ms %v must not be negative", i, s.RTTMs)
		}
		if s.LossPct < 0 || s.LossPct > 100 {
			return fmt.Errorf("paths[%d]: loss_pct %v must be between 0 and 100", i, s.LossPct)
		}
		if len(s.RTTsMs) > 1000 {
			return fmt.Errorf("paths[%d]: rtts_ms has %d entries; the maximum is 1000", i, len(s.RTTsMs))
		}
		for j, ms := range s.RTTsMs {
			if ms < 0 {
				return fmt.Errorf("paths[%d]: rtts_ms[%d] %v must not be negative", i, j, ms)
			}
		}
		if len(s.RTTsMs) > 0 && s.RTTMs != 0 {
			return fmt.Errorf("paths[%d]: set rtts_ms or rtt_ms, not both", i)
		}
		if len(s.RTTsMs) > 0 && s.LossPct != 0 {
			return fmt.Errorf("paths[%d]: rtts_ms cannot be combined with loss_pct", i)
		}
		key := s.Provider + "\x00" + s.Target + "\x00" + strconv.Itoa(s.Count)
		if seen[key] {
			return fmt.Errorf("paths[%d]: duplicate provider %q for this target and count", i, s.Provider)
		}
		seen[key] = true
		out[i] = s
	}
	p.paths = out
	return nil
}

// matchPath returns the first most-specific path. A set target is more
// specific than a set count, and either beats a provider-wide path.
func matchPath(paths []PathSpec, provider, target string, count int) (PathSpec, bool) {
	bestScore := -1
	var best PathSpec
	found := false
	for _, s := range paths {
		if s.Provider != provider {
			continue
		}
		if s.Target != "" && s.Target != target {
			continue
		}
		if s.Count > 0 && s.Count != count {
			continue
		}
		score := 0
		if s.Target != "" {
			score += 2
		}
		if s.Count > 0 {
			score++
		}
		if !found || score > bestScore {
			best, bestScore, found = s, score, true
		}
	}
	return best, found
}

func (p *Prober) readFile() (snapshot, error) {
	st, err := os.Stat(p.file)
	if err != nil {
		return snapshot{}, fmt.Errorf("fixed prober: read %s: %w", p.file, err)
	}
	if st.Size() > maxFile {
		return snapshot{}, fmt.Errorf("fixed prober: %s is larger than %d bytes", p.file, maxFile)
	}
	data, err := os.ReadFile(p.file)
	if err != nil {
		return snapshot{}, fmt.Errorf("fixed prober: read %s: %w", p.file, err)
	}
	var snap snapshot
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&snap); err != nil {
		return snapshot{}, fmt.Errorf("fixed prober: %s: %w", p.file, err)
	}
	if snap.Sent < 0 {
		return snapshot{}, fmt.Errorf("fixed prober: %s: sent %d must not be negative", p.file, snap.Sent)
	}
	if snap.RTTMs < 0 {
		return snapshot{}, fmt.Errorf("fixed prober: %s: rtt_ms %v must not be negative", p.file, snap.RTTMs)
	}
	return snap, nil
}

// snapshot is the on-disk schema (no file field, so a file cannot point at another file).
type snapshot struct {
	Sent  int        `yaml:"sent"`
	RTTMs float64    `yaml:"rtt_ms"`
	Paths []PathSpec `yaml:"paths"`
}

// Probe implements plugin.Prober.
func (p *Prober) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	sent := p.sent
	rtt := p.rttMs
	paths := p.paths
	if p.file != "" {
		snap, err := p.readFile()
		if err != nil {
			return plugin.ProbeResult{}, err
		}
		tmp := &Prober{}
		if err := tmp.setPaths(snap.Paths); err != nil {
			return plugin.ProbeResult{}, fmt.Errorf("fixed prober: %s: %w", p.file, err)
		}
		sent, rtt, paths = snap.Sent, snap.RTTMs, tmp.paths
	}
	spec, ok := matchPath(paths, req.Provider, req.Target.String(), req.Count)
	if !ok {
		if len(paths) > 0 {
			return plugin.ProbeResult{}, fmt.Errorf("fixed prober: no result for provider %q", req.Provider)
		}
		spec = PathSpec{Sent: sent, RTTMs: rtt}
	}
	if spec.SourceDown {
		return plugin.ProbeResult{}, fmt.Errorf("provider %s: %w", req.Provider, plugin.ErrSourceUnavailable)
	}
	return fixedResult(spec, sent, rtt, req.Count), nil
}

// fixedResult turns one path into the raw probe result. rtts_ms is the
// reply list, one entry per reply, so a test can set an RTT spread.
// Otherwise every reply uses one RTT and loss_pct drops some of them.
func fixedResult(spec PathSpec, topSent int, topRTT float64, reqCount int) plugin.ProbeResult {
	if len(spec.RTTsMs) > 0 {
		rtts := make([]time.Duration, len(spec.RTTsMs))
		for i, ms := range spec.RTTsMs {
			rtts[i] = time.Duration(ms * float64(time.Millisecond))
		}
		n := spec.Sent
		if n == 0 {
			n = reqCount
		}
		if n < len(rtts) {
			n = len(rtts)
		}
		return plugin.ProbeResult{Sent: n, RTTs: rtts}
	}
	n := spec.Sent
	if n == 0 {
		n = topSent
	}
	if n == 0 {
		n = reqCount
	}
	if n < 1 {
		n = 1
	}
	ms := spec.RTTMs
	if ms == 0 {
		ms = topRTT
	}
	loss := spec.LossPct
	received := n
	if loss > 0 {
		received = int(math.Round(float64(n) * (1 - loss/100)))
		if received < 0 {
			received = 0
		}
		if received > n {
			received = n
		}
	}
	rtts := make([]time.Duration, received)
	d := time.Duration(ms * float64(time.Millisecond))
	for i := range rtts {
		rtts[i] = d
	}
	return plugin.ProbeResult{Sent: n, RTTs: rtts}
}
