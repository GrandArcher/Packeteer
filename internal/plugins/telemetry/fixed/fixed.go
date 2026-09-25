// Package fixed is a telemetry plugin that reports configured usage and
// never polls a device. It exists so labs and tests can drive commit
// control without an SNMP agent. Do not use it for a real edge: the
// numbers are whatever the file says, not a measurement.
//
// A file, when set, is re-read on every Snapshot, so a lab can change the
// billable figure without restarting Packeteer. The plugin does not announce.
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

// maxFile is how large a usage file may be.
const maxFile = 1 << 20

// maxMbps matches the snmp commit cap.
const maxMbps = 100000000

func init() { plugin.Telemetries.Register(TypeName, New) }

// Config is the fixed telemetry plugin's config block.
type Config struct {
	// File is re-read on every snapshot. Its contents are a list of
	// providers in this same schema, without the file field.
	File      string     `yaml:"file"`
	Providers []Provider `yaml:"providers"`
}

// Provider is one configured usage row.
type Provider struct {
	Name       string  `yaml:"name"`
	CommitMbps float64 `yaml:"commit_mbps"`
	UsageMbps  float64 `yaml:"usage_mbps"`
}

// Collector returns the configured rows.
type Collector struct {
	plugin.Base
	file      string
	providers []Provider
	names     []string
	known     []string // nil means the caller did not ask for a name check
}

// New validates config and, when a file is set, reads it once. It does no I/O
// beyond that read.
func New(c plugin.Config, env plugin.Env) (plugin.Telemetry, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	col := &Collector{file: cfg.File, known: env.Providers}
	if cfg.File == "" && len(cfg.Providers) == 0 {
		return nil, fmt.Errorf("fixed telemetry: set providers or file")
	}
	if err := validate(cfg.Providers, env.Providers); err != nil {
		return nil, err
	}
	col.providers = cfg.Providers
	names := make([]string, 0, len(cfg.Providers))
	for _, p := range cfg.Providers {
		names = append(names, p.Name)
	}
	if cfg.File != "" {
		rows, err := readFile(cfg.File)
		if err != nil {
			return nil, err
		}
		if err := validate(rows, env.Providers); err != nil {
			return nil, fmt.Errorf("fixed telemetry: %s: %w", cfg.File, err)
		}
		for _, p := range rows {
			names = append(names, p.Name)
		}
	}
	col.names = names
	return col, nil
}

// ProviderNames lists providers named in the config block and in the file
// at startup. Snapshot checks the file again on each read.
func (c *Collector) ProviderNames() []string {
	out := make([]string, 0, len(c.names))
	seen := map[string]bool{}
	for _, name := range c.names {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// Snapshot implements plugin.Telemetry. A file is re-read each call.
// Updated is the read time so a commit scorer does not age the row out.
func (c *Collector) Snapshot(ctx context.Context) ([]plugin.Usage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows := c.providers
	if c.file != "" {
		var err error
		rows, err = readFile(c.file)
		if err != nil {
			return nil, err
		}
		if err := validate(rows, c.known); err != nil {
			return nil, err
		}
	}
	now := time.Now()
	out := make([]plugin.Usage, 0, len(rows))
	for _, p := range rows {
		out = append(out, plugin.Usage{
			Provider: p.Name, CommitMbps: p.CommitMbps, Samples: 1, Single: true,
			UsageMbps: p.UsageMbps, Mode: plugin.PercentileGreaterSeparate,
			Updated: now, Polled: now,
		})
	}
	return out, nil
}

func validate(rows []Provider, known []string) error {
	seen := map[string]bool{}
	for i, p := range rows {
		if p.Name == "" {
			return fmt.Errorf("providers[%d]: name is required", i)
		}
		if seen[p.Name] {
			return fmt.Errorf("providers[%d]: duplicate provider %q", i, p.Name)
		}
		seen[p.Name] = true
		if known != nil && !listed(known, p.Name) {
			return fmt.Errorf("providers[%d]: provider %q is not configured", i, p.Name)
		}
		if math.IsNaN(p.CommitMbps) || math.IsInf(p.CommitMbps, 0) || p.CommitMbps <= 0 || p.CommitMbps > maxMbps {
			return fmt.Errorf("providers[%d]: commit_mbps must be greater than 0 and at most 100000000", i)
		}
		if math.IsNaN(p.UsageMbps) || math.IsInf(p.UsageMbps, 0) || p.UsageMbps < 0 || p.UsageMbps > maxMbps {
			return fmt.Errorf("providers[%d]: usage_mbps must be between 0 and 100000000", i)
		}
	}
	return nil
}

func listed(known []string, name string) bool {
	for _, n := range known {
		if n == name {
			return true
		}
	}
	return false
}

func readFile(path string) ([]Provider, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("fixed telemetry: read %s: %w", path, err)
	}
	if st.Size() > maxFile {
		return nil, fmt.Errorf("fixed telemetry: %s is larger than %d bytes", path, maxFile)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("fixed telemetry: read %s: %w", path, err)
	}
	var snap struct {
		Providers []Provider `yaml:"providers"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&snap); err != nil {
		return nil, fmt.Errorf("fixed telemetry: %s: %w", path, err)
	}
	if len(snap.Providers) == 0 {
		return nil, fmt.Errorf("fixed telemetry: %s: providers is empty", path)
	}
	return snap.Providers, nil
}
