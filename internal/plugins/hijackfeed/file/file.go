// Package file is the local hijack feed (#401): a mounted JSON file of
// hijack incidents, such as an export from an outside monitor. It is read
// again when its size or modification time changes. It only reads and is
// evidence only: it never announces and never changes a decision.
package file

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "file"

// Bounds, so a wrong file cannot exhaust memory.
const (
	maxFile      = 16 << 20
	maxIncidents = 100_000
)

func init() { plugin.HijackFeeds.Register(TypeName, New) }

// Config is the plugin's config block.
type Config struct {
	// Path is the file inside the container.
	Path string `yaml:"path"`
}

type document struct {
	Incidents []struct {
		Prefix string `json:"prefix"`
		Origin uint32 `json:"origin"`
		Detail string `json:"detail"`
	} `json:"incidents"`
}

// Feed answers from the file.
type Feed struct {
	plugin.Base
	path string
	log  *slog.Logger

	mu sync.Mutex
	// triedSize and triedMod are the file last read, good or not, so a
	// broken file is not parsed again until it changes.
	triedSize int64
	triedMod  time.Time
	cur       []plugin.HijackIncident
	loaded    bool
	err       error
}

// New is the plugin factory. It validates the config and reads nothing.
func New(c plugin.Config, env plugin.Env) (plugin.HijackFeed, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Path) == "" {
		return nil, errors.New("path is required")
	}
	log := env.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Feed{path: cfg.Path, log: log}, nil
}

// Start reads the file once. A missing or broken file is logged, not
// fatal: lookups fail until it is fixed, and a failed lookup is no
// evidence either way.
func (f *Feed) Start(context.Context) error {
	if _, err := f.load(); err != nil {
		f.log.Warn("hijack feed file not loaded", "path", f.path, "err", err)
	}
	return nil
}

// Incidents implements plugin.HijackFeed.
func (f *Feed) Incidents(_ context.Context, prefix netip.Prefix) ([]plugin.HijackIncident, error) {
	all, err := f.load()
	if err != nil {
		return nil, err
	}
	prefix = prefix.Masked()
	var out []plugin.HijackIncident
	for _, in := range all {
		if in.Prefix.Overlaps(prefix) {
			out = append(out, in)
		}
	}
	return out, nil
}

// load returns the incidents, reading the file first when it changed. A
// file that does not parse keeps the last good list; a removed file is an
// error, so its old incidents stop counting.
func (f *Feed) load() ([]plugin.HijackIncident, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fi, err := os.Stat(f.path)
	if err != nil {
		f.cur, f.loaded, f.triedSize, f.triedMod = nil, false, 0, time.Time{}
		return nil, fmt.Errorf("hijack feed file: %w", err)
	}
	if fi.Size() != f.triedSize || !fi.ModTime().Equal(f.triedMod) {
		f.triedSize, f.triedMod = fi.Size(), fi.ModTime()
		list, rerr := read(f.path)
		if rerr != nil {
			f.err = rerr
			f.log.Warn("hijack feed file not loaded", "path", f.path, "err", rerr)
		} else {
			f.cur, f.loaded, f.err = list, true, nil
		}
	}
	if !f.loaded {
		return nil, f.err
	}
	return f.cur, nil
}

func read(path string) ([]plugin.HijackIncident, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFile {
		return nil, fmt.Errorf("larger than %d bytes", maxFile)
	}
	var doc document
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if len(doc.Incidents) > maxIncidents {
		return nil, fmt.Errorf("more than %d incidents", maxIncidents)
	}
	out := make([]plugin.HijackIncident, 0, len(doc.Incidents))
	for i, in := range doc.Incidents {
		p, err := netip.ParsePrefix(strings.TrimSpace(in.Prefix))
		if err != nil {
			return nil, fmt.Errorf("incidents[%d]: %w", i, err)
		}
		out = append(out, plugin.HijackIncident{Prefix: p.Masked(), Origin: in.Origin, Detail: in.Detail})
	}
	return out, nil
}
