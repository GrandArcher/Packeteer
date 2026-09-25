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
	"os"
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

// PathSpec is one provider's fixed result.
type PathSpec struct {
	Provider   string  `yaml:"provider"`
	Sent       int     `yaml:"sent"`
	RTTMs      float64 `yaml:"rtt_ms"`
	LossPct    float64 `yaml:"loss_pct"`
	SourceDown bool    `yaml:"source_down"`
}

// Prober returns configured probe results.
type Prober struct {
	plugin.Base
	file  string
	sent  int
	rttMs float64
	paths map[string]PathSpec
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
	m := map[string]PathSpec{}
	for i, s := range paths {
		if s.Provider == "" {
			return fmt.Errorf("paths[%d]: provider is required", i)
		}
		if _, dup := m[s.Provider]; dup {
			return fmt.Errorf("paths[%d]: duplicate provider %q", i, s.Provider)
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
		m[s.Provider] = s
	}
	p.paths = m
	return nil
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
	spec, ok := paths[req.Provider]
	if !ok {
		if len(paths) > 0 {
			return plugin.ProbeResult{}, fmt.Errorf("fixed prober: no result for provider %q", req.Provider)
		}
		spec = PathSpec{Sent: sent, RTTMs: rtt}
	}
	if spec.SourceDown {
		return plugin.ProbeResult{}, fmt.Errorf("provider %s: %w", req.Provider, plugin.ErrSourceUnavailable)
	}
	n := spec.Sent
	if n == 0 {
		n = sent
	}
	if n == 0 {
		n = req.Count
	}
	if n < 1 {
		n = 1
	}
	ms := spec.RTTMs
	if ms == 0 {
		ms = rtt
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
	return plugin.ProbeResult{Sent: n, RTTs: rtts}, nil
}
