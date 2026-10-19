package herd

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Audit is one served records response.
type Audit struct {
	Puller  string
	Remote  string
	Query   string
	Records int
}

// ServerOptions wires the pull API.
type ServerOptions struct {
	Cfg   *config.Herd
	ASN   uint32
	Node  *Node
	Store plugin.HerdStore
	// RIB is checked again when a record is served: a route that has left
	// the view is not shared.
	RIB   RIB
	Rules *Rules
	// Peers are the pinned keys, by key id; Hub adds the hub peers' keys.
	// Only these connect.
	Peers map[string]ed25519.PublicKey
	Hub   *KeySet
	Now   func() time.Time
	Log   *slog.Logger
	Trips *Trips
	// Active, when set, gates serving: a standby HA node answers 503.
	Active func() bool
	// Audit receives every served records response.
	Audit func(Audit)
}

// Server is the pull API: GET /herd/v1/status and /herd/v1/records on its
// own listener, mutual TLS with pinned keys, read-only. Every limit is
// enforced here, by the instance being protected.
type Server struct {
	o    ServerOptions
	lim  config.HerdLimits
	byID *limiterSet
	byIP *limiterSet
	all  *rate.Limiter

	ln     net.Listener
	srv    *http.Server
	gate   *gate
	wg     sync.WaitGroup
	hs     chan struct{}
	closed atomic.Bool

	mu    sync.Mutex
	conns int
	perID map[string]int
	live  map[net.Conn]struct{}
}

// NewServer returns a Server. Start opens the listener.
func NewServer(o ServerOptions) *Server {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	l := o.Cfg.Limits
	return &Server{
		o: o, lim: l,
		byID: newLimiterSet(l.RatePerIdentity), byIP: newLimiterSet(l.RatePerAddress),
		all:   rate.NewLimiter(rate.Limit(float64(l.RateGlobal)/60), max(l.RateGlobal, maxCost)),
		hs:    make(chan struct{}, l.MaxHandshakes),
		perID: map[string]int{}, live: map[net.Conn]struct{}{},
	}
}

// Addr is the bound address, for tests that listen on port 0.
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Start listens and serves until Stop.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.o.Cfg.Listen)
	if err != nil {
		return fmt.Errorf("herd listen %s: %w", s.o.Cfg.Listen, err)
	}
	s.ln = ln
	s.gate = &gate{s: s, ready: make(chan net.Conn, s.lim.MaxConns), done: make(chan struct{}), tls: &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{s.o.Node.cert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: pinnedBy(func(id string) bool { _, ok := s.o.Peers[id]; return ok || s.o.Hub.Has(id) }),
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PathStatus, s.handle)
	mux.HandleFunc("GET "+PathRecords, s.handle)
	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: s.lim.Timeout,
		ReadTimeout:       s.lim.Timeout,
		WriteTimeout:      s.lim.Timeout,
		IdleTimeout:       s.lim.IdleTimeout,
		MaxHeaderBytes:    s.lim.MaxRequestBytes,
		ConnContext:       connContext,
		ErrorLog:          slog.NewLogLogger(s.o.Log.Handler(), slog.LevelDebug),
	}
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		s.acceptLoop()
	}()
	go func() {
		defer s.wg.Done()
		if err := s.srv.Serve(s.gate); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.o.Log.Error("herd server", "err", err)
		}
	}()
	s.o.Log.Info("herd pull API listening (mutual TLS, pinned keys)", "addr", ln.Addr().String(), "key", s.o.Node.ID())
	return nil
}

// Stop closes the listener and every connection.
func (s *Server) Stop() {
	if s.ln == nil || !s.closed.CompareAndSwap(false, true) {
		return
	}
	_ = s.ln.Close()
	close(s.gate.done)
	_ = s.srv.Close()
	s.mu.Lock()
	for c := range s.live {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) trip(limit, peer string) { s.o.Trips.Add(limit, peer) }

// gate hands connections that passed admission and the handshake to the
// HTTP server.
type gate struct {
	s     *Server
	ready chan net.Conn
	done  chan struct{}
	tls   *tls.Config
}

func (g *gate) Accept() (net.Conn, error) {
	select {
	case c := <-g.ready:
		return c, nil
	case <-g.done:
		return nil, net.ErrClosed
	}
}
func (g *gate) Close() error   { return nil }
func (g *gate) Addr() net.Addr { return g.s.ln.Addr() }

// tconn is an admitted connection: the TLS connection over raw. Closing it
// releases its slots once.
type tconn struct {
	net.Conn
	raw  net.Conn
	s    *Server
	id   string
	reqs atomic.Int64
	once sync.Once
}

func (c *tconn) Close() error {
	c.once.Do(func() { c.s.release(c.raw, c.id) })
	return c.Conn.Close()
}

type connKey struct{}

func connContext(ctx context.Context, c net.Conn) context.Context {
	if tc, ok := c.(*tconn); ok {
		return context.WithValue(ctx, connKey{}, tc)
	}
	return ctx
}

func (s *Server) release(c net.Conn, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns--
	delete(s.live, c)
	if id != "" {
		if s.perID[id]--; s.perID[id] <= 0 {
			delete(s.perID, id)
		}
	}
}

func (s *Server) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if s.closed.Load() {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		s.admit(c)
	}
}

// admit applies the limits that need no handshake, then hands the
// connection to a handshake goroutine. A connection over a limit is closed
// before any TLS or HTTP work is done for it.
func (s *Server) admit(c net.Conn) {
	ip := remoteIP(c.RemoteAddr())
	if ok, _ := s.byIP.reserve(ip, 1, s.o.Now()); !ok {
		s.trip("rate_per_address", "")
		_ = c.Close()
		return
	}
	s.mu.Lock()
	if s.conns >= s.lim.MaxConns {
		s.mu.Unlock()
		s.trip("max_conns", "")
		_ = c.Close()
		return
	}
	select {
	case s.hs <- struct{}{}:
	default:
		s.mu.Unlock()
		s.trip("max_handshakes", "")
		_ = c.Close()
		return
	}
	s.conns++
	s.live[c] = struct{}{}
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.handshake(c)
	}()
}

func (s *Server) handshake(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(s.lim.Timeout))
	tc := tls.Server(c, s.gate.tls)
	err := tc.Handshake()
	<-s.hs
	if err != nil {
		s.trip("handshake_refused", "")
		s.release(c, "")
		_ = c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	id := KeyID(tc.ConnectionState().PeerCertificates[0].PublicKey.(ed25519.PublicKey))
	s.mu.Lock()
	over := s.perID[id] >= s.lim.MaxConnsPerPeer
	if !over {
		s.perID[id]++
	}
	s.mu.Unlock()
	if over {
		s.trip("max_conns_per_peer", id)
		s.release(c, "")
		_ = tc.Close()
		return
	}
	conn := &tconn{Conn: tc, raw: c, s: s, id: id}
	select {
	case s.gate.ready <- conn:
	default:
		_ = conn.Close()
	}
}

func remoteIP(a net.Addr) string {
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.IP.String()
	}
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	tc, _ := r.Context().Value(connKey{}).(*tconn)
	if tc == nil {
		http.Error(w, "no connection", http.StatusInternalServerError)
		return
	}
	if s.o.Active != nil && !s.o.Active() {
		writeError(w, http.StatusServiceUnavailable, "this node is not the active instance")
		return
	}
	if tc.reqs.Add(1) > int64(s.lim.MaxRequestsPerConn) {
		s.trip("max_requests_per_conn", tc.id)
		w.Header().Set("Connection", "close")
		writeError(w, http.StatusTooManyRequests, "too many requests on this connection")
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		writeError(w, http.StatusBadRequest, "a request body is not allowed")
		return
	}
	if len(r.URL.RawQuery) > s.lim.MaxRequestBytes {
		writeError(w, http.StatusBadRequest, "request too large")
		return
	}
	now := s.o.Now()
	if !s.admitRequest(w, tc, 1, now) {
		return
	}
	if r.URL.Path == PathStatus {
		if r.URL.RawQuery != "" {
			writeError(w, http.StatusBadRequest, "the status document takes no parameters")
			return
		}
		body, _ := s.Status()
		writeJSONBytes(w, http.StatusOK, body)
		return
	}
	q, err := ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if q.Match == MatchCovering || q.Match == MatchCovered {
		if !s.admitRequest(w, tc, maxCost-1, now) {
			return
		}
	}
	code, body, n := s.respond(q, now)
	writeJSONBytes(w, code, body)
	if code == http.StatusOK && s.o.Audit != nil {
		s.o.Audit(Audit{Puller: tc.id, Remote: remoteIP(tc.RemoteAddr()), Query: r.URL.RawQuery, Records: n})
	}
}

// admitRequest charges the source address, the peer identity, and the
// global budget. Over any of them the caller gets 429 and Retry-After.
func (s *Server) admitRequest(w http.ResponseWriter, tc *tconn, cost int, now time.Time) bool {
	if ok, d := s.byIP.reserve(remoteIP(tc.RemoteAddr()), cost, now); !ok {
		s.trip("rate_per_address", tc.id)
		tooMany(w, d)
		return false
	}
	if ok, d := s.byID.reserve(tc.id, cost, now); !ok {
		s.trip("rate_per_identity", tc.id)
		tooMany(w, d)
		return false
	}
	r := s.all.ReserveN(now, cost)
	if !r.OK() {
		tooMany(w, time.Minute)
		return false
	}
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now)
		s.trip("rate_global", tc.id)
		tooMany(w, d)
		return false
	}
	return true
}

func tooMany(w http.ResponseWriter, d time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter(d)))
	writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
}

func writeError(w http.ResponseWriter, code int, msg string) {
	b, _ := json.Marshal(map[string]string{"error": msg})
	writeJSONBytes(w, code, b)
}

func writeJSONBytes(w http.ResponseWriter, code int, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

// Status is the signed status document.
func (s *Server) Status() ([]byte, Status) {
	c := s.o.Cfg
	st := Status{
		Schema: Schema, Member: s.o.Node.ID(), ASN: s.o.ASN, GeneratedAt: s.o.Now().UTC().Truncate(time.Millisecond),
		RetentionDays: c.RetentionDays, Granularity: c.Share.Granularity, Classes: c.Share.Classes,
		Discovery: c.Share.Discovery, Vantage: c.Vantage.Country,
	}
	st.Signature, _ = s.o.Node.sign(st)
	b, _ := json.Marshal(st)
	return b, st
}

// Preview is the response a puller would get for raw, produced by the same
// code that serves real pulls. It is not rate limited and is not audited.
func (s *Server) Preview(raw string) (int, []byte) {
	q, err := ParseQuery(raw)
	if err != nil {
		b, _ := json.Marshal(map[string]string{"error": err.Error()})
		return http.StatusBadRequest, b
	}
	code, body, _ := s.respond(q, s.o.Now())
	return code, body
}

// respond answers a records query: the status code, the signed body, and
// how many records it holds.
func (s *Server) respond(q Query, now time.Time) (int, []byte, int) {
	c := s.o.Cfg
	fail := func(msg string) (int, []byte, int) {
		b, _ := json.Marshal(map[string]string{"error": msg})
		return http.StatusBadRequest, b, 0
	}
	if c.Share.Discovery == config.HerdQueryOnly && q.OriginASN == 0 && q.Prefix == "" {
		return fail("this member answers only for an origin_asn or a prefix you name")
	}
	limit := s.lim.PageRecords
	if q.Limit != 0 {
		limit = min(q.Limit, limit)
	}
	floor := now.Add(-time.Duration(c.RetentionDays) * 24 * time.Hour).UTC().Truncate(time.Millisecond)
	from := floor
	if q.From != "" {
		if t, _ := time.Parse(time.RFC3339Nano, q.From); t.After(from) {
			from = t.UTC()
		}
	}
	hq := plugin.HerdQuery{OriginASN: q.OriginASN, ProviderASN: q.ProviderASN, From: from, Limit: limit + 1}
	if q.To != "" {
		hq.To, _ = time.Parse(time.RFC3339Nano, q.To)
	}
	if q.Prefix != "" {
		hq.Prefix, hq.Match = netip.MustParsePrefix(q.Prefix), q.Match
	}
	var after *plugin.HerdRecord
	if q.Cursor != "" {
		k, err := decodeCursor(q.Cursor)
		if err != nil {
			return fail(err.Error())
		}
		after = &plugin.HerdRecord{ID: k.ID, Member: k.Member, ProviderASN: k.Provider, Time: time.UnixMilli(k.TimeMS)}
		if k.Prefix != "" {
			after.Prefix = netip.MustParsePrefix(k.Prefix)
		}
	}
	env := Envelope{
		Schema: Schema, Member: s.o.Node.ID(), ASN: s.o.ASN, GeneratedAt: now.UTC().Truncate(time.Millisecond),
		RetentionDays: c.RetentionDays, Granularity: c.Share.Granularity, Records: []Record{},
		Query: Query{
			OriginASN: q.OriginASN, Prefix: q.Prefix, Match: q.Match, ProviderASN: q.ProviderASN,
			From: from.Format(time.RFC3339Nano), To: q.To, Limit: limit, Cursor: q.Cursor, Nonce: q.Nonce,
		},
	}
	// A member sharing at origin-ASN level matches no prefix query.
	if q.Prefix == "" || c.Share.Granularity == config.HerdRoute {
		s.fill(&env, hq, after, limit)
	}
	sig, err := s.o.Node.sign(env)
	if err != nil {
		return fail("cannot sign")
	}
	env.Signature = sig
	b, _ := json.Marshal(env)
	return http.StatusOK, b, len(env.Records)
}

// fill adds the servable records after the cursor, stopping at the record
// limit, the response byte cap, or the work cap. When it stops with rows
// left it sets NextCursor to the last row it examined.
func (s *Server) fill(env *Envelope, hq plugin.HerdQuery, after *plugin.HerdRecord, limit int) {
	const overhead = 2048
	size := overhead
	examined, work := 0, 20*s.lim.PageRecords
	hq.Limit = min(limit*2+1, work)
	for {
		hq.After = after
		rows, err := s.o.Store.HerdRecords(context.Background(), hq)
		if err != nil {
			s.o.Log.Warn("herd serve read", "err", err)
			return
		}
		for _, row := range rows {
			if len(env.Records) >= limit || examined >= work {
				env.NextCursor = cursorOf(after)
				return
			}
			examined++
			rec, ok := s.servable(row)
			if ok {
				b, _ := json.Marshal(rec)
				if size+len(b)+1 > s.lim.ResponseBytes && len(env.Records) > 0 {
					env.NextCursor = cursorOf(after)
					return
				}
				size += len(b) + 1
				env.Records = append(env.Records, rec)
			}
			r := row
			after = &r
		}
		if len(rows) < hq.Limit {
			return
		}
	}
}

func cursorOf(r *plugin.HerdRecord) string {
	if r == nil {
		return ""
	}
	k := cursorKey{Provider: r.ProviderASN, TimeMS: r.Time.UnixMilli(), Member: r.Member, ID: r.ID}
	if r.Prefix.IsValid() {
		k.Prefix = r.Prefix.String()
	}
	return encodeCursor(k)
}

// servable decodes a stored own record and applies today's RIB view and
// rules to it: the current granularity and data classes, and for every
// route behind it the exact prefix with a path through its provider, the
// exclude list (against both the stored and the current path), own
// prefixes, and source opt-in. A pooled record with even one route that
// now fails is dropped whole, because it cannot be un-pooled.
func (s *Server) servable(row plugin.HerdRecord) (Record, bool) {
	var rec Record
	if json.Unmarshal(row.Body, &rec) != nil || rec.Granularity != s.o.Cfg.Share.Granularity {
		return rec, false
	}
	var routes []Route
	if json.Unmarshal(row.Meta, &routes) != nil || len(routes) == 0 || !s.o.RIB.Ready() {
		return rec, false
	}
	for _, rt := range routes {
		path, ok := learnedPath(s.o.RIB, rt.Prefix, rt.Provider)
		cur := rt
		cur.Path = path
		if !ok || !s.o.Rules.Allowed(rt) || !s.o.Rules.Allowed(cur) {
			return rec, false
		}
	}
	if !slices.Contains(s.o.Cfg.Share.Classes, config.HerdPaths) {
		rec.ASPath, rec.ASPaths = nil, nil
	}
	return rec, true
}
