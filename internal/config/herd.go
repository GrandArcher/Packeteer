package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Herd is opt-in sharing of probe measurements with other operators'
// Packeteer instances (#260, docs/design/herd.md). Nil or disabled is off:
// nothing is stored, served, or pulled. Herd data never enters Decide and
// herd never announces.
type Herd struct {
	Enabled bool `yaml:"enabled"`
	// PreviewOnly stores and previews records but serves and pulls nothing.
	PreviewOnly bool      `yaml:"preview_only"`
	Share       HerdShare `yaml:"share"`
	// RetentionDays is how long records are kept and served, 30 to 365
	// (default 90).
	RetentionDays int         `yaml:"retention_days"`
	Vantage       HerdVantage `yaml:"vantage"`
	// Listen is the pull API address (mutual TLS, pinned keys), apart from
	// the ops HTTP server.
	Listen string `yaml:"listen"`
	// KeyFile is this node's Ed25519 key, created on first start.
	KeyFile string     `yaml:"key_file"`
	Peers   []HerdPeer `yaml:"peers"`
	Limits  HerdLimits `yaml:"limits"`
}

// HerdShare chooses what leaves the box.
type HerdShare struct {
	// Granularity is origin_asn (default) or route.
	Granularity string `yaml:"granularity"`
	// Classes are the data classes: measurements, and paths (adds the AS
	// path). At least one is required.
	Classes []string `yaml:"classes"`
	// Sources are the target source types whose probes may be shared:
	// static, vip, outage (default), flow, span.
	Sources []string `yaml:"sources"`
	// Discovery is query_only (default) or listing.
	Discovery string      `yaml:"discovery"`
	Exclude   HerdExclude `yaml:"exclude"`
}

// HerdExclude lists what is never shared. A prefix excludes every route
// equal to, inside, or covering it. An ASN excludes every route whose
// origin is that ASN or whose AS path contains it.
type HerdExclude struct {
	Prefixes []string `yaml:"prefixes"`
	ASNs     []uint32 `yaml:"asns"`
}

// HerdVantage is where this node declares it measures from.
type HerdVantage struct {
	// Country is an ISO 3166-1 alpha-2 code. Declared, not geolocated.
	Country string `yaml:"country"`
}

// HerdPeer is a static peer: its pull API address and its pinned key,
// "ed25519:" and the base64 of the 32-byte public key.
type HerdPeer struct {
	URL string `yaml:"url"`
	Key string `yaml:"key"`
}

// HerdLimits are the local resource limits (docs/design/herd.md, Resource
// protection). Zero takes the default; the limit tag is default, minimum,
// and maximum, and a value outside the range is a config error. Rates are
// requests per minute.
type HerdLimits struct {
	// Serving.
	RatePerIdentity    int           `yaml:"rate_per_identity" limit:"60,1,100000"`
	RateGlobal         int           `yaml:"rate_global" limit:"600,1,1000000"`
	RatePerAddress     int           `yaml:"rate_per_address" limit:"120,1,100000"`
	MaxConns           int           `yaml:"max_conns" limit:"64,1,10000"`
	MaxConnsPerPeer    int           `yaml:"max_conns_per_peer" limit:"4,1,1000"`
	MaxHandshakes      int           `yaml:"max_handshakes" limit:"8,1,1000"`
	MaxRequestsPerConn int           `yaml:"max_requests_per_conn" limit:"100,1,100000"`
	MaxRequestBytes    int           `yaml:"max_request_bytes" limit:"4096,512,65536"`
	PageRecords        int           `yaml:"page_records" limit:"200,1,5000"`
	ResponseBytes      int           `yaml:"response_bytes" limit:"1048576,4096,67108864"`
	Timeout            time.Duration `yaml:"timeout" limit:"10s,1s,2m"`
	IdleTimeout        time.Duration `yaml:"idle_timeout" limit:"30s,1s,10m"`
	// Pulling.
	PullInterval       time.Duration `yaml:"pull_interval" limit:"5m,30s,24h"`
	PullTimeout        time.Duration `yaml:"pull_timeout" limit:"20s,1s,5m"`
	MaxPulls           int           `yaml:"max_pulls" limit:"2,1,64"`
	PullRequests       int           `yaml:"pull_requests" limit:"64,1,10000"`
	PeerRequests       int           `yaml:"peer_requests" limit:"16,1,1000"`
	PullBytes          int           `yaml:"pull_bytes" limit:"2097152,4096,67108864"`
	PullRecords        int           `yaml:"pull_records" limit:"500,1,10000"`
	PeerRecordsPerPull int           `yaml:"peer_records_per_pull" limit:"5000,1,1000000"`
	PeerRecordsTotal   int           `yaml:"peer_records_total" limit:"200000,1,100000000"`
	BackoffMax         time.Duration `yaml:"backoff_max" limit:"1h,1s,24h"`
	// Memory and disk. Queue is the batches of results waiting for the
	// herd goroutine; the byte limits cap the stored record bodies.
	Queue       int   `yaml:"queue" limit:"256,1,100000"`
	LocalBytes  int64 `yaml:"local_bytes" limit:"536870912,1048576,1099511627776"`
	PulledBytes int64 `yaml:"pulled_bytes" limit:"536870912,1048576,1099511627776"`
}

// Herd defaults and bounds.
const (
	DefaultHerdRetentionDays = 90
	MinHerdRetentionDays     = 30
	MaxHerdRetentionDays     = 365
	MaxHerdPeers             = 16
	DefaultHerdKeyFile       = "/var/lib/packeteer/herd/node.key"
)

// Herd values.
const (
	HerdOriginASN    = "origin_asn"
	HerdRoute        = "route"
	HerdMeasurements = "measurements"
	HerdPaths        = "paths"
	HerdQueryOnly    = "query_only"
	HerdListing      = "listing"
)

// HerdOn reports whether herd is enabled.
func (c *Config) HerdOn() bool { return c.Herd != nil && c.Herd.Enabled }

// Serving reports whether the pull API listens and peers are pulled.
func (h *Herd) Serving() bool { return h.Enabled && !h.PreviewOnly }

// HerdSourceTypes are the target source types a record may come from.
var HerdSourceTypes = []string{"static", "vip", "outage", "flow", "span"}

// limitFields calls fn for every limit field with its yaml name and tag.
func (l *HerdLimits) limitFields(fn func(name string, v reflect.Value, def, min, max int64)) {
	rv := reflect.ValueOf(l).Elem()
	rt := rv.Type()
	for i := range rt.NumField() {
		f := rt.Field(i)
		tag, ok := f.Tag.Lookup("limit")
		if !ok {
			continue
		}
		parts := strings.Split(tag, ",")
		var vals [3]int64
		for j, p := range parts {
			if rv.Field(i).Type() == reflect.TypeOf(time.Duration(0)) {
				d, err := time.ParseDuration(p)
				if err != nil {
					panic("config: bad limit tag on " + f.Name)
				}
				vals[j] = int64(d)
				continue
			}
			n, err := strconv.ParseInt(p, 10, 64)
			if err != nil {
				panic("config: bad limit tag on " + f.Name)
			}
			vals[j] = n
		}
		fn(f.Tag.Get("yaml"), rv.Field(i), vals[0], vals[1], vals[2])
	}
}

func (l *HerdLimits) applyDefaults() {
	l.limitFields(func(_ string, v reflect.Value, def, _, _ int64) {
		if v.Int() == 0 {
			v.SetInt(def)
		}
	})
}

func (c *Config) defaultHerd() {
	h := c.Herd
	if h == nil || !h.Enabled {
		return
	}
	if h.Share.Granularity == "" {
		h.Share.Granularity = HerdOriginASN
	}
	if len(h.Share.Sources) == 0 {
		h.Share.Sources = []string{"static", "vip", "outage"}
	}
	if h.Share.Discovery == "" {
		h.Share.Discovery = HerdQueryOnly
	}
	if h.RetentionDays == 0 {
		h.RetentionDays = DefaultHerdRetentionDays
	}
	if h.KeyFile == "" {
		h.KeyFile = DefaultHerdKeyFile
	}
	h.Limits.applyDefaults()
}

// ParseHerdKey decodes "ed25519:<base64>" into the 32-byte public key.
func ParseHerdKey(s string) ([]byte, error) {
	b64, ok := strings.CutPrefix(s, "ed25519:")
	if !ok {
		return nil, errors.New(`must start with "ed25519:"`)
	}
	k, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, errors.New("must be the base64 of a 32-byte Ed25519 public key")
	}
	return k, nil
}

// PrefixList is the exclude prefixes, parsed. Validate has already
// checked them.
func (e HerdExclude) PrefixList() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(e.Prefixes))
	for _, s := range e.Prefixes {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

func (c *Config) validateHerd(add func(string, ...any)) {
	h := c.Herd
	if h == nil || !h.Enabled {
		return
	}
	if c.IXP != nil {
		add("herd cannot be used with ixp: IXP mode shares nothing and sends nothing off the box")
	}
	for _, p := range c.Probers {
		if p.Type == "fixed" {
			add("herd: the fixed prober (labs) produces nothing that may be shared; remove it or turn herd off")
		}
	}
	switch h.Share.Granularity {
	case HerdOriginASN, HerdRoute:
	default:
		add("herd.share.granularity %q must be %s or %s", h.Share.Granularity, HerdOriginASN, HerdRoute)
	}
	switch h.Share.Discovery {
	case HerdQueryOnly, HerdListing:
	default:
		add("herd.share.discovery %q must be %s or %s", h.Share.Discovery, HerdQueryOnly, HerdListing)
	}
	if len(h.Share.Classes) == 0 {
		add("herd.share.classes: choose at least one data class (%s, %s)", HerdMeasurements, HerdPaths)
	}
	for i, cl := range h.Share.Classes {
		if cl != HerdMeasurements && cl != HerdPaths {
			add("herd.share.classes[%d]: %q must be %s or %s", i, cl, HerdMeasurements, HerdPaths)
		}
	}
	for i, s := range h.Share.Sources {
		if !slices.Contains(HerdSourceTypes, s) {
			add("herd.share.sources[%d]: %q must be one of %s", i, s, strings.Join(HerdSourceTypes, ", "))
			continue
		}
		// Route level flow and span records need the crowd threshold, which
		// needs verified identities (a later phase).
		if h.Share.Granularity == HerdRoute && (s == "flow" || s == "span") {
			add("herd.share.sources[%d]: %s targets come from user traffic and cannot be shared at route level yet (needs the crowd threshold)", i, s)
		}
	}
	for i, s := range h.Share.Exclude.Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			add("herd.share.exclude.prefixes[%d]: %q is not a prefix", i, s)
		} else if p != p.Masked() {
			add("herd.share.exclude.prefixes[%d]: %q has host bits set", i, s)
		}
	}
	for i, a := range h.Share.Exclude.ASNs {
		if a == 0 {
			add("herd.share.exclude.asns[%d]: 0 is not an ASN", i)
		}
	}
	if h.RetentionDays < MinHerdRetentionDays || h.RetentionDays > MaxHerdRetentionDays {
		add("herd.retention_days %d must be between %d and %d", h.RetentionDays, MinHerdRetentionDays, MaxHerdRetentionDays)
	}
	if cc := h.Vantage.Country; len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		add("herd.vantage.country %q must be an ISO 3166-1 alpha-2 code in capitals", cc)
	}
	if !filepath.IsAbs(h.KeyFile) {
		add("herd.key_file %q must be an absolute path", h.KeyFile)
	}
	h.Limits.limitFields(func(name string, v reflect.Value, _, min, max int64) {
		if n := v.Int(); n < min || n > max {
			add("herd.limits.%s %d must be between %d and %d", name, n, min, max)
		}
	})
	if h.PreviewOnly {
		if h.Listen != "" || len(h.Peers) > 0 {
			add("herd.preview_only serves and pulls nothing: remove herd.listen and herd.peers")
		}
		return
	}
	if _, _, err := net.SplitHostPort(h.Listen); err != nil {
		add("herd.listen %q must be host:port (or set herd.preview_only)", h.Listen)
	}
	if len(h.Peers) == 0 {
		add("herd.peers: at least one peer is required to serve or pull (or set herd.preview_only)")
	}
	if len(h.Peers) > MaxHerdPeers {
		add("herd.peers: at most %d peers", MaxHerdPeers)
	}
	urls, keys := map[string]bool{}, map[string]bool{}
	for i, p := range h.Peers {
		u, err := url.Parse(p.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
			add("herd.peers[%d]: url %q must be https://host:port", i, p.URL)
		} else if _, _, err := net.SplitHostPort(u.Host); err != nil {
			add("herd.peers[%d]: url %q needs a port", i, p.URL)
		}
		if _, err := ParseHerdKey(p.Key); err != nil {
			add("herd.peers[%d]: key %s", i, err)
		}
		if urls[p.URL] || keys[p.Key] {
			add("herd.peers[%d]: duplicate url or key", i)
		}
		urls[p.URL], keys[p.Key] = true, true
	}
}
