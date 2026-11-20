package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net"
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
	// Hub is the public list of herd servers used as seeds (#261). Nil
	// means no hub: only the static peers are used.
	Hub *HerdHub `yaml:"hub"`
	// Identity is where member identities are checked (#672). Nil means
	// none: no member is verified.
	Identity *HerdIdentity `yaml:"identity"`
	// Block and DownWeight are this node's own view of other members
	// (#686): a blocked member is neither pulled nor shown, a down-weighted
	// one is shown in rows and left out of every count. Neither changes
	// what other nodes see.
	Block      HerdMembers `yaml:"block"`
	DownWeight HerdMembers `yaml:"down_weight"`
	Limits     HerdLimits  `yaml:"limits"`
	// Outside is the opt-in outside intelligence on the herd dashboard
	// (#296). Each source is off until chosen. It is shown apart from herd
	// data, never counted as a vantage, and never read by Decide.
	Outside HerdOutside `yaml:"outside"`
}

// HerdOutside chooses the outside sources shown on the herd dashboard.
type HerdOutside struct {
	// Atlas reads public RIPE Atlas results and the status of the
	// operator's own hosted probes.
	Atlas HerdAtlas `yaml:"atlas"`
	// RIS shows the routes the leak watch's rislive sources saw outside
	// this AS (#199). It needs leak_watch with a rislive source.
	RIS bool `yaml:"ris"`
	// RPKI shows the origin validation of a route from the configured rpki
	// source (#158). It needs rpki.
	RPKI bool `yaml:"rpki"`
	// Links shows link-outs (RIPEstat, Cloudflare Radar, and the rest of
	// the linkouts sites) for the selected prefix or ASN. It makes no
	// request.
	Links bool `yaml:"links"`
}

// HerdAtlas reads RIPE Atlas without an API key: public measurements and
// public probe pages only.
type HerdAtlas struct {
	Enabled bool `yaml:"enabled"`
	// Measurements are public measurement ids, for example an anchor mesh
	// ping. Only ping results are shown.
	Measurements []int `yaml:"measurements"`
	// Probes are the operator's own hosted probe ids.
	Probes []int `yaml:"probes"`
	// Refresh is how often Atlas is read again (default 15m).
	Refresh time.Duration `yaml:"refresh"`
}

// HerdHub is the hub list a node fetches over HTTPS to find seed peers.
// Every entry in it is verified by this node; the hub is never trusted.
type HerdHub struct {
	// URL is the https address of the list document.
	URL string `yaml:"url"`
	// Refresh is how often the list is fetched again (default 6h).
	Refresh time.Duration `yaml:"refresh"`
	// MaxPeers caps the peers taken from the list (default 16).
	MaxPeers int `yaml:"max_peers"`
	// ExchangePeers caps the peers learned from other peers' peer lists
	// (peer exchange, #672), apart from the hub peers (default 16).
	ExchangePeers int `yaml:"exchange_peers"`
}

// HerdIdentity reads the validated RPKI Signed Checklists (RFC 9323) that
// bind node keys to ASNs, as a relying party reports them. A member whose
// node key is listed for its ASN is verified; the others are shown and not
// counted.
type HerdIdentity struct {
	// URL is the https address of the checklist document.
	URL string `yaml:"url"`
	// Refresh is how often it is fetched again (default 1h).
	Refresh time.Duration `yaml:"refresh"`
}

// HerdMembers names members by identity (ASN), node key id (the hex
// SHA-256 of the public key, key_id in GET /api/herd), or pull API
// endpoint (https://host:port).
type HerdMembers struct {
	ASNs      []uint32 `yaml:"asns"`
	Keys      []string `yaml:"keys"`
	Endpoints []string `yaml:"endpoints"`
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
	Discovery string `yaml:"discovery"`
	// CrowdK is the crowd threshold (#672): at route level, a route only
	// flow or span listed is served once at least this many other verified
	// ASNs serve records for that exact route (default 2).
	CrowdK int `yaml:"crowd_k"`
	// Exclude is what is never shared. A prefix excludes every route
	// equal to, inside, or covering it. An ASN excludes every route whose
	// origin is that ASN or whose AS path contains it.
	Exclude ExcludeList `yaml:"exclude"`
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
	DefaultHerdHubRefresh    = 6 * time.Hour
	MinHerdHubRefresh        = 10 * time.Minute
	MaxHerdHubRefresh        = 7 * 24 * time.Hour
	DefaultHerdHubPeers      = 16
	MaxHerdHubPeers          = 64
	DefaultHerdIDRefresh     = time.Hour
	MinHerdIDRefresh         = 10 * time.Minute
	MaxHerdIDRefresh         = 24 * time.Hour
	DefaultHerdCrowdK        = 2
	MaxHerdCrowdK            = 64
	DefaultHerdAtlasRefresh  = 15 * time.Minute
	MinHerdAtlasRefresh      = 15 * time.Minute
	MaxHerdAtlasRefresh      = 24 * time.Hour
	MaxHerdAtlasIDs          = 4
	MaxHerdViewEntries       = 256
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

// HerdLimitSpec is the default and range of one herd.limits key. A duration
// key carries nanoseconds.
type HerdLimitSpec struct {
	Key               string
	Duration          bool
	Default, Min, Max int64
}

// HerdLimitSpecs lists the herd.limits keys in file order, for the settings
// form, so the form cannot drift from the loader's defaults and ranges.
func HerdLimitSpecs() []HerdLimitSpec {
	var out []HerdLimitSpec
	var l HerdLimits
	l.limitFields(func(name string, v reflect.Value, def, lo, hi int64) {
		out = append(out, HerdLimitSpec{Key: name, Duration: v.Type() == reflect.TypeOf(time.Duration(0)), Default: def, Min: lo, Max: hi})
	})
	return out
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
	if h.Hub != nil {
		if h.Hub.Refresh == 0 {
			h.Hub.Refresh = DefaultHerdHubRefresh
		}
		if h.Hub.MaxPeers == 0 {
			h.Hub.MaxPeers = DefaultHerdHubPeers
		}
		if h.Hub.ExchangePeers == 0 {
			h.Hub.ExchangePeers = DefaultHerdHubPeers
		}
	}
	if h.Identity != nil && h.Identity.Refresh == 0 {
		h.Identity.Refresh = DefaultHerdIDRefresh
	}
	if h.Share.CrowdK == 0 {
		h.Share.CrowdK = DefaultHerdCrowdK
	}
	h.Limits.applyDefaults()
	if h.Outside.Atlas.Enabled && h.Outside.Atlas.Refresh == 0 {
		h.Outside.Atlas.Refresh = DefaultHerdAtlasRefresh
	}
}

// CheckHerdURL checks a herd endpoint address: https://host:port, nothing
// else.
func CheckHerdURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return errors.New("must be https://host:port")
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return errors.New("needs a port")
	}
	return nil
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

func (c *Config) validateHerd(add func(string, ...any)) {
	h := c.Herd
	for i, s := range c.Sources {
		if s.Type == "herd_hints" && (h == nil || !h.Serving()) {
			add("sources[%d]: type %s needs herd enabled and serving: its hints come from pulled records", i, s.Type)
		}
	}
	if h == nil || !h.Enabled {
		return
	}
	if c.IXP != nil {
		add("herd cannot be used with ixp: IXP mode shares nothing and sends nothing off the box")
	}
	if c.Storage == nil || c.Storage.Type != "sqlite" {
		add("herd needs storage type sqlite: herd records live in its tables")
	}
	if len(c.BGP.Neighbors) == 0 {
		add("herd needs bgp.neighbors: records are built from learned routes")
	}
	for _, p := range c.Probers {
		if p.Type == "fixed" || p.Type == "sim" {
			add("herd: the %s prober (labs) produces nothing that may be shared; remove it or turn herd off", p.Type)
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
		// Only verified members count toward the crowd threshold, so
		// without an identity source such a route would never be served.
		if h.Share.Granularity == HerdRoute && (s == "flow" || s == "span") && h.Identity == nil {
			add("herd.share.sources[%d]: %s targets at route level need herd.identity: only verified members count toward crowd_k", i, s)
		}
	}
	if h.Share.CrowdK < 1 || h.Share.CrowdK > MaxHerdCrowdK {
		add("herd.share.crowd_k %d must be between 1 and %d", h.Share.CrowdK, MaxHerdCrowdK)
	}
	h.Share.Exclude.validate(add, "herd.share.exclude")
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
	c.validateHerdOutside(add)
	if h.PreviewOnly {
		if h.Listen != "" || len(h.Peers) > 0 || h.Hub != nil || h.Identity != nil || !h.Block.empty() || !h.DownWeight.empty() {
			add("herd.preview_only serves and pulls nothing: remove herd.listen, herd.peers, herd.hub, herd.identity, herd.block, and herd.down_weight")
		}
		return
	}
	h.validateView(add)
	if _, _, err := net.SplitHostPort(h.Listen); err != nil {
		add("herd.listen %q must be host:port (or set herd.preview_only)", h.Listen)
	}
	if len(h.Peers) == 0 && h.Hub == nil {
		add("herd.peers: at least one peer (or herd.hub) is required to serve or pull (or set herd.preview_only)")
	}
	if len(h.Peers) > MaxHerdPeers {
		add("herd.peers: at most %d peers", MaxHerdPeers)
	}
	if h.Hub != nil {
		h.Hub.validate(add)
	}
	if id := h.Identity; id != nil {
		if u, err := url.Parse(id.URL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			add("herd.identity.url %q must be an https URL", id.URL)
		}
		if id.Refresh < MinHerdIDRefresh || id.Refresh > MaxHerdIDRefresh {
			add("herd.identity.refresh %s must be between %s and %s", id.Refresh, MinHerdIDRefresh, MaxHerdIDRefresh)
		}
	}
	urls, keys := map[string]bool{}, map[string]bool{}
	for i, p := range h.Peers {
		if err := CheckHerdURL(p.URL); err != nil {
			add("herd.peers[%d]: url %q %s", i, p.URL, err)
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

func (m HerdMembers) empty() bool { return len(m.ASNs)+len(m.Keys)+len(m.Endpoints) == 0 }

// validateView checks block and down_weight. A member named in both is an
// error: block already hides it.
func (h *Herd) validateView(add func(string, ...any)) {
	seen := map[string]string{}
	for _, l := range []struct {
		name string
		m    HerdMembers
	}{{"block", h.Block}, {"down_weight", h.DownWeight}} {
		if n := len(l.m.ASNs) + len(l.m.Keys) + len(l.m.Endpoints); n > MaxHerdViewEntries {
			add("herd.%s: at most %d entries", l.name, MaxHerdViewEntries)
		}
		note := func(field string, i int, key string) {
			if prev, dup := seen[key]; dup {
				add("herd.%s.%s[%d]: already listed in herd.%s", l.name, field, i, prev)
				return
			}
			seen[key] = l.name
		}
		for i, a := range l.m.ASNs {
			if a == 0 {
				add("herd.%s.asns[%d]: must be a non-zero ASN", l.name, i)
				continue
			}
			note("asns", i, "asn:"+strconv.FormatUint(uint64(a), 10))
		}
		for i, k := range l.m.Keys {
			if !isHerdKeyID(k) {
				add("herd.%s.keys[%d]: %q must be a key id, 64 lowercase hex digits (key_id in GET /api/herd)", l.name, i, k)
				continue
			}
			note("keys", i, "key:"+k)
		}
		for i, e := range l.m.Endpoints {
			if err := CheckHerdURL(e); err != nil {
				add("herd.%s.endpoints[%d]: %q %s", l.name, i, e, err)
				continue
			}
			note("endpoints", i, "url:"+e)
		}
	}
}

// isHerdKeyID reports whether s is a node key id: the lowercase hex
// SHA-256 of an Ed25519 public key.
func isHerdKeyID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (b *HerdHub) validate(add func(string, ...any)) {
	if u, err := url.Parse(b.URL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		add("herd.hub.url %q must be an https URL", b.URL)
	}
	if b.Refresh < MinHerdHubRefresh || b.Refresh > MaxHerdHubRefresh {
		add("herd.hub.refresh %s must be between %s and %s", b.Refresh, MinHerdHubRefresh, MaxHerdHubRefresh)
	}
	if b.MaxPeers < 1 || b.MaxPeers > MaxHerdHubPeers {
		add("herd.hub.max_peers %d must be between 1 and %d", b.MaxPeers, MaxHerdHubPeers)
	}
	if b.ExchangePeers < 1 || b.ExchangePeers > MaxHerdHubPeers {
		add("herd.hub.exchange_peers %d must be between 1 and %d", b.ExchangePeers, MaxHerdHubPeers)
	}
}

func (c *Config) validateHerdOutside(add func(string, ...any)) {
	o := c.Herd.Outside
	if o.RIS {
		rislive := false
		if c.LeakWatching() {
			for _, src := range c.LeakWatch.Sources {
				rislive = rislive || src.Type == "rislive"
			}
		}
		if !rislive {
			add("herd.outside.ris needs leak_watch enabled with a rislive source")
		}
	}
	if o.RPKI && !c.RPKIOn() {
		add("herd.outside.rpki needs rpki enabled")
	}
	a := o.Atlas
	if !a.Enabled {
		if len(a.Measurements) > 0 || len(a.Probes) > 0 || a.Refresh != 0 {
			add("herd.outside.atlas: set enabled: true to use measurements, probes, or refresh")
		}
		return
	}
	if len(a.Measurements)+len(a.Probes) == 0 {
		add("herd.outside.atlas: name at least one measurement or probe")
	}
	for name, ids := range map[string][]int{"measurements": a.Measurements, "probes": a.Probes} {
		if len(ids) > MaxHerdAtlasIDs {
			add("herd.outside.atlas.%s: at most %d", name, MaxHerdAtlasIDs)
		}
		for i, id := range ids {
			if id <= 0 {
				add("herd.outside.atlas.%s[%d]: %d is not an id", name, i, id)
			}
		}
	}
	if a.Refresh < MinHerdAtlasRefresh || a.Refresh > MaxHerdAtlasRefresh {
		add("herd.outside.atlas.refresh %s must be between %s and %s", a.Refresh, MinHerdAtlasRefresh, MaxHerdAtlasRefresh)
	}
}
