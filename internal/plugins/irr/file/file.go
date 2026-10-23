// Package file is the local IRR source (#214): a mounted file with RPSL
// objects (an IRR database dump, or objects an IRRd instance exports) or
// bgpq4 JSON prefix lists named after their origin AS. The file is read
// again when its size or modification time changes, and its modification
// time is the data time. It only reads: it never announces and never
// changes the learned RIB.
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

	"github.com/GrandArcher/Packeteer/internal/irr"
	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "file"

// File formats.
const (
	FormatRPSL  = "rpsl"
	FormatBGPQ4 = "bgpq4"
)

// Bounds, so a wrong file cannot exhaust memory.
const (
	maxFile   = 4 << 30
	maxRoutes = 10_000_000
)

func init() { plugin.IRRs.Register(TypeName, New) }

// Config is the plugin's config block.
type Config struct {
	// Path is the file inside the container.
	Path string `yaml:"path"`
	// Format is rpsl or bgpq4.
	Format string `yaml:"format"`
}

// span is one registered origin for a prefix and the lengths it covers:
// exactly the prefix for a route object, a bgpq4 range otherwise.
type span struct {
	origin   uint32
	database string
	ge, le   uint8
}

type set struct {
	asns []uint32
	sets []string
}

type data struct {
	routes map[netip.Prefix][]span
	n      int
	sets   map[string]set
	names  map[uint32]string
	at     time.Time
}

// Source answers from the file.
type Source struct {
	plugin.Base
	cfg Config
	log *slog.Logger

	mu sync.Mutex
	// tried is the size and time of the file last read, good or not, so a
	// broken file is not read again until it changes.
	triedSize int64
	triedMod  time.Time
	cur       *data
	err       error
}

// New is the plugin factory. It validates the config and reads nothing.
func New(c plugin.Config, env plugin.Env) (plugin.IRR, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Path) == "" {
		return nil, errors.New("path is required")
	}
	switch cfg.Format {
	case "":
		cfg.Format = FormatRPSL
	case FormatRPSL, FormatBGPQ4:
	default:
		return nil, fmt.Errorf("format %q must be %s or %s", cfg.Format, FormatRPSL, FormatBGPQ4)
	}
	log := env.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Source{cfg: cfg, log: log}, nil
}

// Start reads the file once. A missing or broken file is logged, not
// fatal: lookups fail until it is fixed, and IRR is display only unless
// irr.prefer_registered is set, which fails open.
func (s *Source) Start(context.Context) error {
	if _, err := s.load(); err != nil {
		s.log.Warn("irr file not loaded", "path", s.cfg.Path, "err", err)
	}
	return nil
}

// load returns the current data, reading the file first when it changed.
// A read that fails keeps the last good data.
func (s *Source) load() (*data, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fi, err := os.Stat(s.cfg.Path)
	if err != nil {
		if s.cur != nil {
			return s.cur, nil
		}
		return nil, fmt.Errorf("irr file: %w", err)
	}
	if fi.Size() == s.triedSize && fi.ModTime().Equal(s.triedMod) {
		if s.cur == nil {
			return nil, s.err
		}
		return s.cur, nil
	}
	s.triedSize, s.triedMod = fi.Size(), fi.ModTime()
	d, err := s.read(fi)
	if err != nil {
		s.err = fmt.Errorf("irr file %s: %w", s.cfg.Path, err)
		s.log.Warn("irr file not loaded, keeping the last good data", "path", s.cfg.Path, "err", err)
		if s.cur == nil {
			return nil, s.err
		}
		return s.cur, nil
	}
	s.cur, s.err = d, nil
	return d, nil
}

func (s *Source) read(fi os.FileInfo) (*data, error) {
	if fi.Size() > maxFile {
		return nil, fmt.Errorf("larger than %d bytes", int64(maxFile))
	}
	f, err := os.Open(s.cfg.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d := &data{routes: map[netip.Prefix][]span{}, sets: map[string]set{}, names: map[uint32]string{}, at: fi.ModTime()}
	r := io.LimitReader(f, maxFile)
	if s.cfg.Format == FormatBGPQ4 {
		err = readBGPQ4(r, d)
	} else {
		err = readRPSL(r, d)
	}
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (d *data) add(p netip.Prefix, sp span) error {
	if d.n >= maxRoutes {
		return fmt.Errorf("more than %d routes", maxRoutes)
	}
	d.routes[p] = append(d.routes[p], sp)
	d.n++
	return nil
}

func readRPSL(r io.Reader, d *data) error {
	return irr.ParseRPSL(r, func(o irr.Object) error {
		switch o.Class() {
		case "route", "route6":
			rt, ok := irr.Route(o)
			if !ok {
				return nil
			}
			bits := uint8(rt.Prefix.Bits())
			return d.add(rt.Prefix, span{origin: rt.Origin, database: rt.Database, ge: bits, le: bits})
		case "as-set":
			asns, sets := irr.Members(o)
			d.sets[strings.ToUpper(o[0].Value)] = set{asns: asns, sets: sets}
		case "aut-num":
			if asn, ok := netpfx.ParseASN(o[0].Value); ok {
				d.names[asn] = o.Get("as-name")
			}
		}
		return nil
	})
}

// bgpq4Entry is one entry of `bgpq4 -j` output.
type bgpq4Entry struct {
	Prefix       string `json:"prefix"`
	Exact        bool   `json:"exact"`
	GreaterEqual *uint8 `json:"greater-equal"`
	LessEqual    *uint8 `json:"less-equal"`
}

// readBGPQ4 reads one or more concatenated `bgpq4 -j -l AS<n> AS<n>`
// documents. The list name is the origin, because a bgpq4 list does not
// carry one.
func readBGPQ4(r io.Reader, d *data) error {
	dec := json.NewDecoder(r)
	for {
		var doc map[string][]bgpq4Entry
		if err := dec.Decode(&doc); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return fmt.Errorf("bgpq4 json: %w", err)
		}
		for name, entries := range doc {
			origin, ok := netpfx.ParseASN(name)
			if !ok {
				return fmt.Errorf("bgpq4 list %q: name each list after its origin AS (bgpq4 -l AS64500)", name)
			}
			for _, e := range entries {
				p, err := netip.ParsePrefix(e.Prefix)
				if err != nil {
					return fmt.Errorf("bgpq4 list %q: %w", name, err)
				}
				bits := uint8(p.Bits())
				sp := span{origin: origin, ge: bits, le: bits}
				if !e.Exact {
					if e.GreaterEqual != nil {
						sp.ge = *e.GreaterEqual
					}
					if e.LessEqual != nil {
						sp.le = *e.LessEqual
					}
				}
				if sp.ge < bits || sp.le < sp.ge || int(sp.le) > p.Addr().BitLen() {
					return fmt.Errorf("bgpq4 list %q: bad range on %s", name, p)
				}
				if err := d.add(p.Masked(), sp); err != nil {
					return err
				}
			}
		}
	}
}

// Routes returns the registered origins for exactly prefix: route objects
// for the prefix, or bgpq4 entries whose range covers it.
func (s *Source) Routes(_ context.Context, prefix netip.Prefix) ([]plugin.IRRRoute, time.Time, error) {
	d, err := s.load()
	if err != nil {
		return nil, time.Time{}, err
	}
	prefix = prefix.Masked()
	bits := prefix.Bits()
	var out []plugin.IRRRoute
	for i := 0; i <= bits; i++ {
		cover := netip.PrefixFrom(prefix.Addr(), i).Masked()
		for _, sp := range d.routes[cover] {
			if int(sp.ge) <= bits && bits <= int(sp.le) {
				out = append(out, plugin.IRRRoute{Prefix: prefix, Origin: sp.origin, Database: sp.database})
			}
		}
	}
	return out, d.at, nil
}

// ASSetMembers expands an as-set from the file's as-set objects.
func (s *Source) ASSetMembers(_ context.Context, name string) ([]uint32, time.Time, error) {
	if s.cfg.Format == FormatBGPQ4 {
		return nil, time.Time{}, plugin.ErrIRRUnsupported
	}
	d, err := s.load()
	if err != nil {
		return nil, time.Time{}, err
	}
	out, err := irr.Expand(name, func(n string) ([]uint32, []string, bool, error) {
		st, ok := d.sets[strings.ToUpper(n)]
		return st.asns, st.sets, ok, nil
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	return out, d.at, nil
}

// ASName returns the as-name of the file's aut-num object for asn.
func (s *Source) ASName(_ context.Context, asn uint32) (string, time.Time, error) {
	if s.cfg.Format == FormatBGPQ4 {
		return "", time.Time{}, plugin.ErrIRRUnsupported
	}
	d, err := s.load()
	if err != nil {
		return "", time.Time{}, err
	}
	return d.names[asn], d.at, nil
}
