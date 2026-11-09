package herd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// RIB is the learned-route view records are checked against. *rib.View
// implements it. Only routes present in it are ever recorded.
type RIB interface {
	Ready() bool
	Exact(netip.Prefix) (rib.Route, bool)
	ProviderPaths(netip.Prefix, string) [][]uint32
}

// maxOrigins bounds the origin ASNs a node remembers to ask peers about.
const maxOrigins = 4096

// RecorderOptions wires a Recorder.
type RecorderOptions struct {
	Cfg   *config.Herd
	Node  *Node
	Store plugin.HerdStore
	RIB   RIB
	Rules *Rules
	// Methods maps a prober name to icmp, tcp, or udp. A prober not in it
	// (exec, fixed) produces nothing that is shared.
	Methods map[string]string
	// FirstMethod labels a failed round, which names no prober.
	FirstMethod string
	// SourceTypes maps a target source name to its type.
	SourceTypes map[string]string
	Now         func() time.Time
	Log         *slog.Logger
	// Event raises an operator event (a herd panic).
	Event func(msg string)
}

// Recorder turns probe rounds into herd records. Offer is the only call
// on the probe loop's path: it hands the round to a bounded queue and
// returns; a full queue drops the round and counts it.
type Recorder struct {
	o       RecorderOptions
	q       chan []probe.Result
	guard   *guard
	dropped atomic.Uint64
	stored  atomic.Uint64

	mu      sync.Mutex
	origins map[uint32]time.Time
}

// NewRecorder returns a Recorder. Run starts its work.
func NewRecorder(o RecorderOptions) *Recorder {
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Recorder{
		o: o, q: make(chan []probe.Result, o.Cfg.Limits.Queue),
		guard: newGuard(o.Log, o.Event), origins: map[uint32]time.Time{},
	}
}

// Offer queues a round without blocking.
func (r *Recorder) Offer(batch []probe.Result) {
	select {
	case r.q <- batch:
	default:
		r.dropped.Add(uint64(len(batch)))
	}
}

// Run processes queued rounds and applies retention and the local disk
// budget until ctx ends.
func (r *Recorder) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r.guard.run(ctx, "recorder", func(ctx context.Context) {
			for {
				select {
				case <-ctx.Done():
					return
				case b := <-r.q:
					r.process(ctx, b)
				}
			}
		})
	}()
	go func() {
		defer wg.Done()
		r.guard.run(ctx, "retention", r.retention)
	}()
	wg.Wait()
}

func (r *Recorder) retention(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		r.prune(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// prune deletes records past retention, own and pulled, and trims own
// records to their disk budget, oldest first.
func (r *Recorder) prune(ctx context.Context) {
	cutoff := r.o.Now().Add(-time.Duration(r.o.Cfg.RetentionDays) * 24 * time.Hour)
	if _, err := r.o.Store.DeleteHerdBefore(ctx, cutoff); err != nil {
		r.o.Log.Warn("herd retention", "err", err)
	}
	if _, err := r.o.Store.TrimHerd(ctx, false, r.o.Cfg.Limits.LocalBytes); err != nil {
		r.o.Log.Warn("herd local budget", "err", err)
	}
}

// Origins are the origin ASNs recorded recently, which a query-only peer
// is asked about.
func (r *Recorder) Origins() []uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]uint32, 0, len(r.origins))
	for a := range r.origins {
		out = append(out, a)
	}
	slices.Sort(out)
	return out
}

func (r *Recorder) noteOrigin(a uint32, at time.Time) {
	if a == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.origins[a]; !ok && len(r.origins) >= maxOrigins {
		var oldest uint32
		var when time.Time
		for k, t := range r.origins {
			if when.IsZero() || t.Before(when) {
				oldest, when = k, t
			}
		}
		delete(r.origins, oldest)
	}
	r.origins[a] = at
}

// Dropped is how many results the full queue refused.
func (r *Recorder) Dropped() uint64 { return r.dropped.Load() }

// Stored is how many records were written.
func (r *Recorder) Stored() uint64 { return r.stored.Load() }

// Restarts is how many times a herd goroutine restarted after a panic.
func (r *Recorder) Restarts() uint64 { return r.guard.restarts.Load() }

type poolKey struct {
	provider    string
	origin      uint32
	providerASN uint32
	method      string
}

// pool is the routes of one origin ASN probed through one provider in one
// batch, pooled into a record the way the probe engine pools hosts.
type pool struct {
	method      string
	provider    string
	providerASN uint32
	origin      uint32
	routes      []Route
	paths       [][]uint32
	sent        int
	hosts       int
	samples     []Sample
	first       time.Time
	failed      bool
}

func (p *pool) add(rt Route, res probe.Result, public []uint32) {
	p.routes = append(p.routes, rt)
	if !slices.ContainsFunc(p.paths, func(q []uint32) bool { return slices.Equal(q, public) }) && len(p.paths) < maxASPaths {
		p.paths = append(p.paths, public)
	}
	if p.first.IsZero() || res.Time.Before(p.first) {
		p.first = res.Time
	}
	if res.Err != "" {
		return
	}
	p.failed = false
	p.sent += sentOf(res)
	p.samples, p.hosts = appendSamples(p.samples, p.hosts, res)
}

func sentOf(res probe.Result) int {
	n := 0
	for _, h := range res.Share.Hosts {
		n += h.Sent
	}
	return n
}

// appendSamples adds the replies of res, numbering hosts from next. A host
// with no replies takes no number, so numbers never skip; Validate refuses
// a gap.
func appendSamples(dst []Sample, next int, res probe.Result) ([]Sample, int) {
	for _, h := range res.Share.Hosts {
		if len(h.RTTs) == 0 {
			continue
		}
		for _, d := range h.RTTs {
			dst = append(dst, Sample{Host: next, RTTMs: float64(d) / float64(time.Millisecond)})
		}
		next++
	}
	return dst, next
}

func (r *Recorder) process(ctx context.Context, batch []probe.Result) {
	if !r.o.RIB.Ready() {
		return
	}
	cfg := r.o.Cfg
	var out []plugin.HerdRecord
	pools := map[poolKey]*pool{}
	var order []poolKey
	for _, res := range batch {
		if res.Share == nil || res.Indirect || len(res.Subranges) > 0 {
			continue
		}
		method := r.o.Methods[res.Prober]
		if res.Err != "" {
			method = r.o.FirstMethod
		}
		if method == "" {
			continue
		}
		if res.Err == "" && len(res.Share.Hosts) == 0 {
			continue
		}
		rt, path, ok := r.route(res)
		if !ok {
			continue
		}
		public := publicPath(path)
		var provider, origin uint32
		if asnShared(path[0]) {
			provider = path[0]
		}
		if last := path[len(path)-1]; asnShared(last) {
			origin = last
		}
		if cfg.Share.Granularity == config.HerdRoute {
			out = append(out, r.routeRecord(res, rt, public, provider, origin, method))
			continue
		}
		if origin == 0 {
			continue
		}
		key := poolKey{res.Provider, origin, provider, method}
		p := pools[key]
		if p != nil && len(p.samples)+maxReplies(res) > maxSamples {
			out = append(out, r.originRecord(p))
			delete(pools, key)
			p = nil
		}
		if p == nil {
			p = &pool{method: method, provider: res.Provider, providerASN: provider, origin: origin, failed: true}
			pools[key] = p
			order = append(order, key)
		}
		p.add(rt, res, public)
	}
	for _, key := range order {
		if p := pools[key]; p != nil {
			out = append(out, r.originRecord(p))
		}
	}
	if len(out) == 0 {
		return
	}
	n, err := r.o.Store.PutHerdRecords(ctx, out)
	if err != nil {
		r.o.Log.Warn("herd store write", "err", err)
		return
	}
	r.stored.Add(uint64(n))
	for _, rec := range out {
		r.noteOrigin(rec.OriginASN, rec.Time)
	}
}

// maxReplies is how many replies res can add to a pool.
func maxReplies(res probe.Result) int {
	n := 0
	for _, h := range res.Share.Hosts {
		n += len(h.RTTs)
	}
	return n
}

// learnedPath returns the AS path the RIB view holds for prefix through
// provider. It fails unless the exact prefix is in the view and the
// provider has a non-empty learned path for it.
func learnedPath(view RIB, prefix netip.Prefix, provider string) ([]uint32, bool) {
	if _, ok := view.Exact(prefix); !ok {
		return nil, false
	}
	for _, p := range view.ProviderPaths(prefix, provider) {
		if len(p) > 0 {
			return p, true
		}
	}
	return nil, false
}

// route returns the learned route behind a result: the exact prefix must be
// in the RIB view, and the provider must have a learned path for it. The
// route is then checked against the rules.
func (r *Recorder) route(res probe.Result) (Route, []uint32, bool) {
	path, ok := learnedPath(r.o.RIB, res.Prefix, res.Provider)
	if !ok {
		return Route{}, nil, false
	}
	var types []string
	for _, name := range res.Share.Sources {
		if t, ok := r.o.SourceTypes[name]; ok && !slices.Contains(types, t) {
			types = append(types, t)
		}
	}
	rt := Route{Prefix: res.Prefix, Provider: res.Provider, Path: path, Sources: types}
	return rt, path, r.o.Rules.Allowed(rt)
}

func (r *Recorder) base(g, method string, at time.Time) Record {
	return Record{
		Schema: Schema, Granularity: g, Vantage: r.o.Cfg.Vantage.Country, Method: method,
		Time: at.UTC().Truncate(time.Millisecond),
	}
}

func (r *Recorder) wantPaths() bool {
	return slices.Contains(r.o.Cfg.Share.Classes, config.HerdPaths)
}

func (r *Recorder) routeRecord(res probe.Result, rt Route, public []uint32, provider, origin uint32, method string) plugin.HerdRecord {
	rec := r.base(config.HerdRoute, method, res.Time)
	rec.Prefix, rec.OriginASN, rec.ProviderASN = rt.Prefix.String(), origin, provider
	if r.wantPaths() && len(public) > 0 {
		rec.ASPath = public
	}
	if res.Err != "" {
		rec.Failed = true
	} else {
		rec.Sent = sentOf(res)
		rec.Samples, _ = appendSamples(nil, 0, res)
		rec.setSummary()
	}
	rec.ID = r.id(res.Provider, rec.Prefix, provider, rec.Time, 0)
	return r.herdRecord(rec, []Route{rt})
}

func (r *Recorder) originRecord(p *pool) plugin.HerdRecord {
	rec := r.base(config.HerdOriginASN, p.method, p.first)
	rec.OriginASN, rec.ProviderASN, rec.Routes = p.origin, p.providerASN, len(p.routes)
	if r.wantPaths() {
		sort.Slice(p.paths, func(i, j int) bool { return slices.Compare(p.paths[i], p.paths[j]) < 0 })
		rec.ASPaths = p.paths
	}
	if p.failed {
		rec.Failed = true
	} else {
		rec.Sent, rec.Samples = p.sent, p.samples
		rec.setSummary()
	}
	rec.ID = r.id(p.provider, fmt.Sprint(p.origin), p.providerASN, rec.Time, len(p.routes))
	return r.herdRecord(rec, p.routes)
}

// id is stable across restarts and unique per member: a hash of the node
// key, the local provider name (never served), the target, and the round.
func (r *Recorder) id(provider, target string, providerASN uint32, at time.Time, salt int) string {
	h := sha256.Sum256(fmt.Appendf(nil, "%s|%s|%s|%d|%d|%d", r.o.Node.ID(), provider, target, providerASN, at.UnixNano(), salt))
	return hex.EncodeToString(h[:16])
}

func (r *Recorder) herdRecord(rec Record, routes []Route) plugin.HerdRecord {
	body, _ := json.Marshal(rec)
	meta, _ := json.Marshal(routes)
	hr := plugin.HerdRecord{
		ID: rec.ID, Granularity: rec.Granularity, OriginASN: rec.OriginASN, ProviderASN: rec.ProviderASN,
		Time: rec.Time, Body: body, Meta: meta,
	}
	if rec.Prefix != "" {
		hr.Prefix = netip.MustParsePrefix(rec.Prefix)
	}
	return hr
}
