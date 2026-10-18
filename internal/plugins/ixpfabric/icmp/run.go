package icmp

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/GrandArcher/Packeteer/internal/plugins/ixpmember/ixf"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// waiter is the packet budget. *rate.Limiter satisfies it.
type waiter interface {
	WaitN(ctx context.Context, n int) error
}

type nagiosPart struct {
	by  map[string]nagiosHost
	ok  bool
	err string
}

type runner struct {
	log       *slog.Logger
	prober    plugin.Prober
	interval  time.Duration
	timeout   time.Duration
	packets   int
	workers   int
	memberPPS int
	global    waiter
	// memberWait, when set, replaces the per-ASN limiter. Tests use it.
	memberWait func(asn uint32) waiter
	apiKey     string
	http       *http.Client
	now        func() time.Time

	mu        sync.Mutex
	members   func() plugin.MemberView
	vantages  []plugin.FabricVantage
	view      plugin.FabricView
	parts     map[string]nagiosPart
	memberLim map[uint32]*rate.Limiter
	cancel    context.CancelFunc
	done      chan struct{}
}

func (r *runner) setMembers(fn func() plugin.MemberView) {
	r.mu.Lock()
	r.members = fn
	r.mu.Unlock()
}

func (r *runner) setVantages(v []plugin.FabricVantage) {
	r.mu.Lock()
	r.vantages = append([]plugin.FabricVantage(nil), v...)
	r.mu.Unlock()
}

func (r *runner) snapshot() plugin.FabricView {
	r.mu.Lock()
	v := r.view
	r.mu.Unlock()
	if v.Vantages == nil {
		v.Vantages = []plugin.FabricVantageStatus{}
	}
	if v.Samples == nil {
		v.Samples = []plugin.FabricSample{}
	}
	return v
}

func (r *runner) start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	r.mu.Lock()
	r.cancel = cancel
	r.done = done
	r.mu.Unlock()
	go r.loop(ctx, done)
	return nil
}

func (r *runner) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	for {
		if ctx.Err() != nil {
			return
		}
		start := r.clock()
		r.runRound(ctx)
		wait := r.interval - r.clock().Sub(start)
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (r *runner) stop(ctx context.Context) error {
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *runner) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

func (r *runner) memberView() plugin.MemberView {
	r.mu.Lock()
	fn := r.members
	r.mu.Unlock()
	if fn == nil {
		return plugin.MemberView{}
	}
	return fn()
}

func (r *runner) vantageCopy() []plugin.FabricVantage {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]plugin.FabricVantage(nil), r.vantages...)
}

// runRound measures the current member list once. A stale or unloaded
// list clears samples and sends nothing: there is no route to withdraw,
// and a stale LAN address must not keep being probed. A cancelled round
// leaves the previous samples in place.
func (r *runner) runRound(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	now := r.clock()
	members := r.memberView()
	vantages := r.vantageCopy()
	if members.Stale || members.Fetched == nil {
		msg := members.Error
		switch {
		case members.Stale && msg == "":
			msg = "member list is stale"
		case members.Fetched == nil && msg == "":
			msg = "member list has not loaded"
		}
		msg = ixf.Redact(msg, r.apiKey)
		r.publish(plugin.FabricView{
			Configured: true,
			Stale:      true,
			Error:      msg,
			Round:      now,
			Vantages:   emptyStatuses(vantages),
			Samples:    []plugin.FabricSample{},
		})
		r.logRound(0, 0, msg)
		return
	}
	r.refreshPolicy(ctx, members, vantages)
	if ctx.Err() != nil {
		return
	}
	parts, polErr := r.policySnapshot()
	targets, optOut, statuses := selectTargets(members, vantages, parts)
	samples := r.probeAll(ctx, targets, now)
	if ctx.Err() != nil {
		return
	}
	applyVantageHealth(statuses, samples)
	keep := map[uint32]bool{}
	for _, t := range targets {
		keep[t.asn] = true
	}
	r.evictMembers(keep)
	r.publish(plugin.FabricView{
		Configured: true,
		Error:      polErr,
		Round:      now,
		Targets:    len(targets),
		OptOut:     optOut,
		Vantages:   statuses,
		Samples:    samples,
	})
	r.logRound(len(targets), optOut, polErr)
}

func (r *runner) logRound(targets, optOut int, err string) {
	if r.log != nil {
		r.log.Info("ixp fabric round", "targets", targets, "opt_out", optOut, "error", err)
	}
}

func emptyStatuses(vantages []plugin.FabricVantage) []plugin.FabricVantageStatus {
	out := make([]plugin.FabricVantageStatus, len(vantages))
	for i, v := range vantages {
		out[i] = plugin.FabricVantageStatus{Name: v.Name, Address: v.Address.String(), VLANID: v.VLANID, IXPID: v.IXPID}
	}
	return out
}

func (r *runner) publish(v plugin.FabricView) {
	if v.Vantages == nil {
		v.Vantages = []plugin.FabricVantageStatus{}
	}
	if v.Samples == nil {
		v.Samples = []plugin.FabricSample{}
	}
	r.mu.Lock()
	r.view = v
	r.mu.Unlock()
}

func (r *runner) refreshPolicy(ctx context.Context, view plugin.MemberView, vantages []plugin.FabricVantage) {
	if !view.Manager || view.URL == "" {
		return
	}
	seen := map[string]bool{}
	for _, v := range vantages {
		if ctx.Err() != nil {
			return
		}
		fam := "ipv4"
		if v.Address.Is6() {
			fam = "ipv6"
		}
		key := famKey(v.VLANID, fam)
		if seen[key] {
			continue
		}
		seen[key] = true
		raw, err := nagiosURL(view.URL, v.VLANID, fam)
		if err != nil {
			r.notePolicyErr(key, err)
			continue
		}
		body, err := r.getNagios(ctx, raw)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			r.notePolicyErr(key, err)
			continue
		}
		hosts, err := parseNagios(body)
		if err != nil {
			r.notePolicyErr(key, err)
			continue
		}
		r.storePolicy(key, hosts)
	}
	r.evictPolicy(seen)
}

func famKey(vlan int, family string) string {
	return family + "/" + strconv.Itoa(vlan)
}

func (r *runner) notePolicyErr(key string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.parts == nil {
		r.parts = map[string]nagiosPart{}
	}
	p := r.parts[key]
	p.err = ixf.Redact(err.Error(), r.apiKey)
	r.parts[key] = p
}

func (r *runner) evictPolicy(keep map[string]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k := range r.parts {
		if !keep[k] {
			delete(r.parts, k)
		}
	}
}

func (r *runner) storePolicy(key string, hosts map[string]nagiosHost) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.parts == nil {
		r.parts = map[string]nagiosPart{}
	}
	r.parts[key] = nagiosPart{by: hosts, ok: true}
}

func (r *runner) policySnapshot() (map[string]map[string]nagiosHost, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]map[string]nagiosHost, len(r.parts))
	keys := make([]string, 0, len(r.parts))
	for k := range r.parts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var errs []string
	for _, k := range keys {
		p := r.parts[k]
		if p.err != "" {
			errs = append(errs, p.err)
		}
		if p.ok || len(p.by) > 0 {
			out[k] = p.by
		}
	}
	return out, strings.Join(errs, "; ")
}

func (r *runner) probeAll(ctx context.Context, targets []target, now time.Time) []plugin.FabricSample {
	if len(targets) == 0 {
		return []plugin.FabricSample{}
	}
	limits := make(map[uint32]waiter, len(targets))
	for _, t := range targets {
		if _, ok := limits[t.asn]; !ok {
			limits[t.asn] = r.limitFor(t.asn)
		}
	}
	workers := r.workers
	if workers < 1 {
		workers = 1
	}
	out := make([]plugin.FabricSample, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i, t := range targets {
		if ctx.Err() != nil {
			out[i] = t.errored(now, "round cancelled")
			continue
		}
		wg.Add(1)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Done()
			out[i] = t.errored(now, "round cancelled")
			continue
		}
		go func(i int, t target) {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = r.probeOne(ctx, t, limits[t.asn], now)
		}(i, t)
	}
	wg.Wait()
	return out
}

func (r *runner) probeOne(ctx context.Context, t target, member waiter, now time.Time) plugin.FabricSample {
	if member != nil {
		if err := member.WaitN(ctx, r.packets); err != nil {
			return t.errored(now, ixf.Redact("member rate limit: "+err.Error(), r.apiKey))
		}
	}
	if r.global != nil {
		if err := r.global.WaitN(ctx, r.packets); err != nil {
			return t.errored(now, ixf.Redact("rate limit: "+err.Error(), r.apiKey))
		}
	}
	to := r.timeout
	if t.busy && t.tol.critRTT > to {
		to = t.tol.critRTT
	}
	res, err := r.prober.Probe(ctx, plugin.ProbeRequest{
		Provider: t.vantage,
		Source:   t.source,
		Target:   t.addr,
		Count:    r.packets,
		Timeout:  to,
	})
	if err != nil {
		return t.errored(now, ixf.Redact(err.Error(), r.apiKey))
	}
	return t.measured(now, res)
}

func (r *runner) limitFor(asn uint32) waiter {
	if r.memberWait != nil {
		return r.memberWait(asn)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.memberLim == nil {
		r.memberLim = map[uint32]*rate.Limiter{}
	}
	if r.memberLim[asn] == nil {
		r.memberLim[asn] = rate.NewLimiter(rate.Limit(r.memberPPS), burst(r.memberPPS, r.packets))
	}
	return r.memberLim[asn]
}

func (r *runner) evictMembers(keep map[uint32]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for asn := range r.memberLim {
		if !keep[asn] {
			delete(r.memberLim, asn)
		}
	}
}

func applyVantageHealth(st []plugin.FabricVantageStatus, samples []plugin.FabricSample) {
	for i := range st {
		if st[i].Error != "" {
			st[i].Up = false
			continue
		}
		n, bad := 0, 0
		first := ""
		for _, s := range samples {
			if s.Vantage != st[i].Name {
				continue
			}
			n++
			if s.Error != "" {
				bad++
				if first == "" {
					first = s.Error
				}
			}
		}
		st[i].Targets = n
		if n > 0 && bad == n {
			st[i].Up = false
			st[i].Error = first
			continue
		}
		st[i].Up = true
	}
}
