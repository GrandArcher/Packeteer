package birdseye

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type server struct {
	cfg  ServerConfig
	base string

	status      plugin.RouteServerStatus
	lastOK      time.Time
	fails       int
	unreachable bool
	sessions    map[string]*sess
	history     map[string][]sample
}

func newServer(cfg ServerConfig, base string) *server {
	return &server{
		cfg:      cfg,
		base:     base,
		status:   plugin.RouteServerStatus{Name: cfg.Name, URL: base, ASN: cfg.ASN},
		sessions: map[string]*sess{},
		history:  map[string][]sample{},
	}
}

// sess is a session's latest row and the alerts open on it.
type sess struct {
	view         plugin.RouteServerSession
	down         bool
	prefixHigh   bool
	filteredHigh bool
}

const (
	flagEstablished = 1 << iota
	flagCounted
)

// sample is a compact history point; a session keeps maxSamples of them.
type sample struct {
	at       int64
	flags    uint8
	received int32
	accepted int32
	filtered int32
	max      int32
	reasons  []plugin.RouteServerReason
}

func (s sample) public() plugin.RouteServerSample {
	r := s.reasons
	if r == nil {
		r = []plugin.RouteServerReason{}
	}
	return plugin.RouteServerSample{
		At:          time.Unix(s.at, 0).UTC(),
		Established: s.flags&flagEstablished != 0,
		Counted:     s.flags&flagCounted != 0,
		Received:    int(s.received),
		Accepted:    int(s.accepted),
		Filtered:    int(s.filtered),
		Reasons:     append([]plugin.RouteServerReason{}, r...),
		MaxPrefix:   int(s.max),
	}
}

// member is what the IX-F list says about one LAN address.
type member struct {
	asn       uint32
	name      string
	maxPrefix int
}

func (w *Watch) memberIndex() map[netip.Addr]member {
	w.mu.Lock()
	fn := w.members
	w.mu.Unlock()
	out := map[netip.Addr]member{}
	if fn == nil {
		return out
	}
	for _, m := range fn().Members {
		for _, c := range m.Connections {
			for _, a := range c.Addresses {
				if addr, err := netip.ParseAddr(a.Address); err == nil {
					out[addr.Unmap()] = member{asn: m.ASN, name: m.Name, maxPrefix: a.MaxPrefix}
				}
			}
		}
	}
	return out
}

// round polls every server once. Servers go one after another; the
// sessions of one server go through a bounded worker pool.
func (w *Watch) round(ctx context.Context, now time.Time) {
	members := w.memberIndex()
	for _, s := range w.servers {
		if ctx.Err() != nil {
			return
		}
		w.pollServer(ctx, s, members, now)
	}
}

func (w *Watch) pollServer(ctx context.Context, s *server, members map[netip.Addr]member, now time.Time) {
	st, err := w.status(ctx, s.base)
	var protos []protocol
	if err == nil {
		protos, err = w.protocols(ctx, s.base)
	}
	if err == nil && len(protos) > maxSessions {
		err = fmt.Errorf("more than %d sessions", maxSessions)
	}
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		w.fail(s, now, err)
		return
	}
	rows := make([]plugin.RouteServerSession, len(protos))
	idx := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < w.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				rows[i] = w.measure(ctx, s, protos[i], members, now)
			}
		}()
	}
	for i := range protos {
		idx <- i
	}
	close(idx)
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	w.apply(s, st, rows, now)
}

// validProtocol keeps a name from Birdseye usable as one URL segment.
func validProtocol(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '.', c == '-':
		default:
			return false
		}
	}
	return true
}

// measure builds one session's row. A session that is not Established has
// no routes, so its counts are zero without asking Birdseye. A failed read
// leaves Counted false with the counts zero and records the error.
func (w *Watch) measure(ctx context.Context, s *server, p protocol, members map[netip.Addr]member, now time.Time) plugin.RouteServerSession {
	v := plugin.RouteServerSession{
		Server:      s.cfg.Name,
		Session:     p.Name,
		ASN:         p.NeighborAS,
		Description: p.Description,
		State:       p.stateText(),
		Established: p.established(),
		Reasons:     []plugin.RouteServerReason{},
		MaxPrefix:   p.ImportLimit,
		At:          now,
	}
	if addr, err := netip.ParseAddr(p.NeighborAddress); err == nil {
		addr = addr.Unmap()
		v.Neighbor = addr.String()
		if m, ok := members[addr]; ok {
			v.Name = m.name
			if v.ASN == 0 {
				v.ASN = m.asn
			}
			if m.maxPrefix > 0 {
				v.MaxPrefix = m.maxPrefix
			}
		}
	}
	if !validProtocol(p.Name) {
		v.Error = "session name is not usable in a URL"
		return v
	}
	if !v.Established {
		v.Counted = true
		return v
	}
	received, err := w.routeCount(ctx, s.base, p.Name)
	if err != nil {
		v.Error = err.Error()
		return v
	}
	var filtered int
	var reasons map[int]int
	if received > 0 {
		filtered, reasons, err = w.filtered(ctx, s.base, p.Name, s.cfg.ASN)
		if err != nil {
			v.Error = err.Error()
			return v
		}
	}
	v.Counted = true
	v.Received = received
	v.Filtered = filtered
	v.Accepted = max(received-filtered, 0)
	for r, n := range reasons {
		v.Reasons = append(v.Reasons, plugin.RouteServerReason{Reason: r, Count: n})
	}
	sort.Slice(v.Reasons, func(i, j int) bool { return v.Reasons[i].Reason < v.Reasons[j].Reason })
	if v.MaxPrefix > 0 {
		v.UsedPct = float64(v.Accepted) * 100 / float64(v.MaxPrefix)
	}
	return v
}

// fail records a failed poll. The sessions keep their last state.
func (w *Watch) fail(s *server, now time.Time, err error) {
	var events []plugin.Event
	w.mu.Lock()
	s.status.Up = false
	s.status.Error = err.Error()
	s.status.Polled = now
	s.fails++
	if s.fails >= failsBeforeAlert && !s.unreachable {
		s.unreachable = true
		events = append(events, plugin.NewEvent(plugin.EventRSUnreachable, now,
			fmt.Sprintf("Birdseye on route server %s is unreachable: %s", s.cfg.Name, err),
			map[string]string{"server": s.cfg.Name, "error": err.Error()}))
	}
	w.mu.Unlock()
	w.log.Warn("route server poll failed", "server", s.cfg.Name, "error", err.Error())
	w.emit(events)
}

// apply publishes a successful poll: the rows, the history, and the events
// for every change since the last one.
func (w *Watch) apply(s *server, st statusDoc, rows []plugin.RouteServerSession, now time.Time) {
	var events []plugin.Event
	w.mu.Lock()
	s.status = plugin.RouteServerStatus{
		Name: s.cfg.Name, URL: s.base, ASN: s.cfg.ASN, Up: true, Polled: now,
		Version: st.Status.Version, RouterID: st.Status.RouterID,
		LastReconf: st.Status.LastReconf, Message: st.Status.Message,
		Sessions: len(rows),
	}
	s.lastOK = now
	s.fails = 0
	if s.unreachable {
		s.unreachable = false
		events = append(events, plugin.NewEvent(plugin.EventRSReachable, now,
			fmt.Sprintf("Birdseye on route server %s answers again", s.cfg.Name),
			map[string]string{"server": s.cfg.Name}))
	}
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		seen[row.Session] = true
		st := s.sessions[row.Session]
		if st == nil {
			st = &sess{}
			s.sessions[row.Session] = st
		}
		events = append(events, w.evaluate(st, row, now)...)
		st.view = row
		s.record(row, now)
	}
	for name, st := range s.sessions {
		if !seen[name] {
			events = append(events, w.resolveAll(st, now)...)
			delete(s.sessions, name)
		}
	}
	s.prune(now, w.interval)
	w.mu.Unlock()
	w.emit(events)
}

func (s *server) record(row plugin.RouteServerSession, now time.Time) {
	smp := sample{
		at:       now.Unix(),
		received: int32(row.Received),
		accepted: int32(row.Accepted),
		filtered: int32(row.Filtered),
		max:      int32(row.MaxPrefix),
	}
	if row.Established {
		smp.flags |= flagEstablished
	}
	if row.Counted {
		smp.flags |= flagCounted
	}
	if len(row.Reasons) > 0 {
		smp.reasons = append([]plugin.RouteServerReason(nil), row.Reasons...)
	}
	h := append(s.history[row.Session], smp)
	if len(h) > maxSamples {
		h = append(h[:0], h[len(h)-maxSamples:]...)
	}
	s.history[row.Session] = h
}

// prune forgets a session that has been gone for the whole history window.
func (s *server) prune(now time.Time, interval time.Duration) {
	window := int64(maxSamples * interval / time.Second)
	for name, h := range s.history {
		if now.Unix()-h[len(h)-1].at >= window {
			delete(s.history, name)
		}
	}
}

func fields(row plugin.RouteServerSession, kv ...string) map[string]string {
	f := map[string]string{
		"server":  row.Server,
		"session": row.Session,
		"asn":     strconv.FormatUint(uint64(row.ASN), 10),
	}
	for i := 0; i+1 < len(kv); i += 2 {
		f[kv[i]] = kv[i+1]
	}
	return f
}

func label(row plugin.RouteServerSession) string {
	if row.Name != "" {
		return fmt.Sprintf("%s (AS%d) on %s", row.Name, row.ASN, row.Server)
	}
	return fmt.Sprintf("AS%d session %s on %s", row.ASN, row.Session, row.Server)
}

// evaluate compares a new row with the alerts open on its session. A first
// sighting raises problems only: a session that is already up, small, and
// clean says nothing. A row whose counts could not be read keeps the
// prefix and filtered alerts as they are.
func (w *Watch) evaluate(st *sess, row plugin.RouteServerSession, now time.Time) []plugin.Event {
	var ev []plugin.Event
	switch {
	case !row.Established && !st.down:
		st.down = true
		ev = append(ev, plugin.NewEvent(plugin.EventRSSessionDown, now,
			fmt.Sprintf("%s is %s", label(row), row.State), fields(row, "neighbor", row.Neighbor, "state", row.State)))
	case row.Established && st.down:
		st.down = false
		ev = append(ev, plugin.NewEvent(plugin.EventRSSessionUp, now,
			fmt.Sprintf("%s is Established", label(row)), fields(row, "neighbor", row.Neighbor, "state", row.State)))
	}
	if !row.Counted {
		return ev
	}
	high := row.MaxPrefix > 0 && row.Accepted*100 >= w.prefPct*row.MaxPrefix
	switch {
	case high && !st.prefixHigh:
		st.prefixHigh = true
		ev = append(ev, plugin.NewEvent(plugin.EventRSMaxPrefix, now,
			fmt.Sprintf("%s: %d accepted of max_prefix %d", label(row), row.Accepted, row.MaxPrefix),
			fields(row, "accepted", strconv.Itoa(row.Accepted), "max_prefix", strconv.Itoa(row.MaxPrefix))))
	case !high && st.prefixHigh:
		st.prefixHigh = false
		ev = append(ev, plugin.NewEvent(plugin.EventRSMaxPrefixCleared, now,
			fmt.Sprintf("%s: %d accepted of max_prefix %d", label(row), row.Accepted, row.MaxPrefix),
			fields(row, "accepted", strconv.Itoa(row.Accepted), "max_prefix", strconv.Itoa(row.MaxPrefix))))
	}
	filt := row.Received > 0 && row.Filtered*100 >= w.filtPct*row.Received
	switch {
	case filt && !st.filteredHigh:
		st.filteredHigh = true
		ev = append(ev, plugin.NewEvent(plugin.EventRSFiltered, now,
			fmt.Sprintf("%s: %d of %d routes are filtered", label(row), row.Filtered, row.Received),
			fields(row, "received", strconv.Itoa(row.Received), "filtered", strconv.Itoa(row.Filtered))))
	case !filt && st.filteredHigh:
		st.filteredHigh = false
		ev = append(ev, plugin.NewEvent(plugin.EventRSFilteredCleared, now,
			fmt.Sprintf("%s: %d of %d routes are filtered", label(row), row.Filtered, row.Received),
			fields(row, "received", strconv.Itoa(row.Received), "filtered", strconv.Itoa(row.Filtered))))
	}
	return ev
}

// resolveAll closes every alert open on a session that left the route
// server, so a pager does not keep an incident for a session that is gone.
func (w *Watch) resolveAll(st *sess, now time.Time) []plugin.Event {
	row := st.view
	var ev []plugin.Event
	if st.down {
		ev = append(ev, plugin.NewEvent(plugin.EventRSSessionUp, now,
			label(row)+" is no longer on the route server", fields(row, "neighbor", row.Neighbor, "state", "removed")))
	}
	if st.prefixHigh {
		ev = append(ev, plugin.NewEvent(plugin.EventRSMaxPrefixCleared, now,
			label(row)+" is no longer on the route server", fields(row, "accepted", "0", "max_prefix", strconv.Itoa(row.MaxPrefix))))
	}
	if st.filteredHigh {
		ev = append(ev, plugin.NewEvent(plugin.EventRSFilteredCleared, now,
			label(row)+" is no longer on the route server", fields(row, "received", "0", "filtered", "0")))
	}
	return ev
}

func (w *Watch) emit(events []plugin.Event) {
	if len(events) == 0 {
		return
	}
	w.mu.Lock()
	sink := w.sink
	w.mu.Unlock()
	if sink == nil {
		return
	}
	for _, e := range events {
		sink(e)
	}
}

// View returns the latest poll. A server with no successful poll for
// staleFactor intervals is Stale and shows no sessions.
func (w *Watch) View() plugin.RouteServerView {
	now := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	v := plugin.RouteServerView{
		Configured: true,
		Servers:    make([]plugin.RouteServerStatus, 0, len(w.servers)),
		Sessions:   []plugin.RouteServerSession{},
	}
	for _, s := range w.servers {
		st := s.status
		if !s.lastOK.IsZero() && now.Sub(s.lastOK) > staleFactor*w.interval {
			st.Stale = true
			st.Up = false
			st.Sessions = 0
			if st.Error == "" {
				st.Error = "route server data is stale"
			}
			v.Servers = append(v.Servers, st)
			continue
		}
		v.Servers = append(v.Servers, st)
		names := make([]string, 0, len(s.sessions))
		for n := range s.sessions {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			row := s.sessions[n].view
			row.Reasons = append([]plugin.RouteServerReason{}, row.Reasons...)
			v.Sessions = append(v.Sessions, row)
		}
	}
	return v
}

// History returns one session's samples, oldest first.
func (w *Watch) History(server, session string) ([]plugin.RouteServerSample, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, s := range w.servers {
		if s.cfg.Name != server {
			continue
		}
		h, ok := s.history[session]
		if !ok {
			return nil, false
		}
		out := make([]plugin.RouteServerSample, len(h))
		for i, smp := range h {
			out[i] = smp.public()
		}
		return out, true
	}
	return nil, false
}
