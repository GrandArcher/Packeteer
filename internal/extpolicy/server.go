package extpolicy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/GrandArcher/Packeteer/internal/auth"
)

// Paths and names a consumer uses.
const (
	// DocumentPath serves the Document as JSON (GET). With ?wait=N it
	// answers as soon as the revision differs from N, or after a
	// heartbeat, so a poller applies a change at once.
	DocumentPath = "/v1/recommendations"
	// ServiceName and WatchMethod are the gRPC stream: the request is a
	// google.protobuf.Empty and each message a google.protobuf.Struct
	// holding the Document's JSON fields.
	ServiceName = "packeteer.policy.v1.Recommendations"
	WatchMethod = "Watch"
	// MinTokenLen is the shortest bearer token the server accepts.
	MinTokenLen = 16
)

// Listener limits. A consumer holds one connection, so the caps are far above
// any real deployment. Requests have no read or write timeout: a long poll
// and the stream are held open on purpose, and only an authorized request
// gets that far. A connection that has not sent a right token within
// authDeadline is closed, so clients without the token hold a slot for
// seconds at most, and one address (an IPv6 /64) holds at most
// maxConnsPerAddr such connections.
const (
	maxConns        = 128
	maxConnsPerAddr = 8
	authDeadline    = 5 * time.Second
	idleTimeout     = time.Minute
)

// ServerConfig is the listener of the feed.
type ServerConfig struct {
	Listen   string
	CertFile string
	KeyFile  string
	// Token is the bearer token every request must carry.
	Token string
}

// Server serves the feed over TLS: the JSON document and the gRPC stream on
// one port, both read-only and behind the bearer token.
type Server struct {
	feed *Feed
	log  *slog.Logger
	cfg  ServerConfig
	hash [sha256.Size]byte
	grpc *grpc.Server
	srv  *http.Server
	ln   *connLimit
	bad  *backoff
	// authWait is authDeadline; tests change it.
	authWait time.Duration
}

// NewServer checks cfg and loads the certificate.
func NewServer(feed *Feed, cfg ServerConfig, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	if len(cfg.Token) < MinTokenLen {
		return nil, fmt.Errorf("external_policy: the token must be at least %d characters", MinTokenLen)
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("external_policy: cert_file/key_file: %w", err)
	}
	s := &Server{feed: feed, log: log, cfg: cfg, hash: sha256.Sum256([]byte(cfg.Token)), bad: newBackoff(time.Now), authWait: authDeadline}
	s.grpc = grpc.NewServer()
	s.grpc.RegisterService(&serviceDesc, s)
	s.srv = &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       idleTimeout,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}},
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc, ok := c.(*tls.Conn); ok {
				c = tc.NetConn()
			}
			if lc, ok := c.(*limitedConn); ok {
				return context.WithValue(ctx, connKey{}, lc)
			}
			return ctx
		},
	}
	return s, nil
}

// Start listens and serves in the background.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("external_policy listen %s: %w", s.cfg.Listen, err)
	}
	s.ln = newConnLimit(ln, maxConns, maxConnsPerAddr, s.authWait)
	go func() {
		if err := s.srv.ServeTLS(s.ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("external policy feed stopped", "err", err)
		}
	}()
	s.log.Info("external policy feed listening", "addr", s.Addr())
	return nil
}

// Addr is the bound address, after Start.
func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Shutdown stops the server. Close the feed first: open streams send the
// empty, expired set and end.
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.srv.Shutdown(ctx)
	if err != nil {
		err = errors.Join(err, s.srv.Close())
	}
	s.grpc.Stop()
	return err
}

func (s *Server) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := auth.RemoteIP(r)
		// While an address backs off its token is not even compared, so
		// guessing runs no faster than the backoff allows.
		if wait := s.bad.wait(ip); wait > 0 {
			// A refused client gives its connection slot back at once.
			w.Header().Set("Connection", "close")
			w.Header().Set("Retry-After", strconv.Itoa(int((wait+time.Second-1)/time.Second)))
			http.Error(w, "too many failed tokens", http.StatusTooManyRequests)
			return
		}
		if !s.authorized(r) {
			if s.bad.fail(ip) {
				s.log.Warn("external policy feed: wrong bearer token; backing off", "remote", ip)
			}
			w.Header().Set("Connection", "close")
			w.Header().Set("WWW-Authenticate", `Bearer realm="packeteer"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.bad.ok(ip)
		if lc, ok := r.Context().Value(connKey{}).(*limitedConn); ok {
			lc.authorized()
		}
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			s.grpc.ServeHTTP(w, r)
			return
		}
		if r.URL.Path != DocumentPath {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
			return
		}
		if v := r.URL.Query().Get("wait"); v != "" {
			rev, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				http.Error(w, "wait must be a revision", http.StatusBadRequest)
				return
			}
			s.waitChange(r.Context(), rev)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(s.feed.Document())
	})
}

// waitChange returns once the revision is not rev, the feed closes, a
// heartbeat passes, or the client goes away.
func (s *Server) waitChange(ctx context.Context, rev uint64) {
	timer := time.NewTimer(s.feed.Heartbeat())
	defer timer.Stop()
	for {
		changed, done := s.feed.Changed()
		if done || s.feed.Document().Revision != rev {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			return
		case <-changed:
		}
	}
}

// authorized compares hashes in constant time, so neither the token nor
// its length leaks through timing.
func (s *Server) authorized(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	got := sha256.Sum256([]byte(tok))
	return subtle.ConstantTimeCompare(got[:], s.hash[:]) == 1
}

var serviceDesc = grpc.ServiceDesc{
	ServiceName: ServiceName,
	HandlerType: (*any)(nil),
	Streams: []grpc.StreamDesc{{
		StreamName:    WatchMethod,
		ServerStreams: true,
		Handler: func(srv any, stream grpc.ServerStream) error {
			if err := stream.RecvMsg(new(emptypb.Empty)); err != nil {
				return err
			}
			return srv.(*Server).watch(stream)
		},
	}},
	Metadata: "docs/recommendations.proto",
}

// watch sends the document now, on every change, and every heartbeat. When
// the feed closes it sends the empty, expired set and ends the stream.
func (s *Server) watch(stream grpc.ServerStream) error {
	ctx := stream.Context()
	tick := time.NewTicker(s.feed.Heartbeat())
	defer tick.Stop()
	for {
		changed, done := s.feed.Changed()
		msg, err := documentStruct(s.feed.Document())
		if err != nil {
			return err
		}
		if err := stream.SendMsg(msg); err != nil {
			return err
		}
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
			tick.Reset(s.feed.Heartbeat())
		case <-tick.C:
		}
	}
}

// documentStruct is the Document's JSON as a Struct.
func documentStruct(d Document) (*structpb.Struct, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return structpb.NewStruct(m)
}

type connKey struct{}

// connLimit caps the open connections in total, and per address key (see
// backoffKey) the ones that have not carried a right token yet. A
// connection over the per-address cap is closed before TLS and does not
// take a slot. A connection not marked authorized within authWait is
// closed. Authorized connections do not count per address, so a consumer
// that leaves idle keep-alive connections behind is not refused.
type connLimit struct {
	net.Listener
	sem       chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	perAddr   int
	authWait  time.Duration
	mu        sync.Mutex
	open      map[netip.Prefix]int
}

func newConnLimit(ln net.Listener, total, perAddr int, authWait time.Duration) *connLimit {
	return &connLimit{Listener: ln, sem: make(chan struct{}, total), done: make(chan struct{}), perAddr: perAddr, authWait: authWait, open: map[netip.Prefix]int{}}
}

func (l *connLimit) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			<-l.sem
			return nil, err
		}
		var ip netip.Addr
		if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			ip = a.AddrPort().Addr().Unmap()
		}
		key := backoffKey(ip)
		l.mu.Lock()
		full := l.open[key] >= l.perAddr
		if !full {
			l.open[key]++
		}
		l.mu.Unlock()
		if full {
			_ = c.Close()
			continue
		}
		lc := &limitedConn{Conn: c, l: l, key: key}
		// The timer closes only the socket; the server then closes lc,
		// which gives the slot back.
		lc.timer = time.AfterFunc(l.authWait, func() {
			if !lc.settled.Load() {
				_ = c.Close()
			}
		})
		return lc, nil
	}
}

// Close also wakes an Accept waiting for a free slot.
func (l *connLimit) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitedConn struct {
	net.Conn
	l     *connLimit
	key   netip.Prefix
	timer *time.Timer
	// settled is set once the connection carried a right token or
	// closed; from then on it does not count against its address.
	settled   atomic.Bool
	closeOnce sync.Once
}

// authorized keeps the connection past authWait once it carried a right
// token.
func (c *limitedConn) authorized() {
	if !c.settled.Swap(true) {
		c.timer.Stop()
		c.l.release(c.key)
	}
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() {
		c.timer.Stop()
		if !c.settled.Swap(true) {
			c.l.release(c.key)
		}
		<-c.l.sem
	})
	return err
}

func (l *connLimit) release(key netip.Prefix) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.open[key]--; l.open[key] <= 0 {
		delete(l.open, key)
	}
}

// Token-failure backoff: after the nth wrong token in a row an address is
// refused for backoffBase << (n-1), at most backoffMax. A right token
// clears it. An address with no failure for backoffForget is forgotten.
const (
	backoffBase   = time.Second
	backoffMax    = time.Minute
	backoffForget = 10 * time.Minute
	// maxBackoffKeys bounds the table; past it a new address is not
	// tracked until old entries are forgotten.
	maxBackoffKeys = 4096
)

type backoff struct {
	mu    sync.Mutex
	now   func() time.Time
	fails map[netip.Prefix]*failState
}

type failState struct {
	n     int
	last  time.Time
	until time.Time
}

func newBackoff(now func() time.Time) *backoff {
	return &backoff{now: now, fails: map[netip.Prefix]*failState{}}
}

// backoffKey is the address, or its /64 for IPv6, where one host usually
// has the whole /64.
func backoffKey(ip netip.Addr) netip.Prefix {
	bits := 32
	if !ip.Is4() {
		bits = 64
	}
	p, _ := ip.Prefix(bits)
	return p
}

// wait is how long ip is still refused.
func (b *backoff) wait(ip netip.Addr) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if f := b.fails[backoffKey(ip)]; f != nil {
		return max(f.until.Sub(b.now()), 0)
	}
	return 0
}

// fail counts a wrong token from ip. It reports whether ip was not backing
// off before, so the caller logs an address once, not on every guess.
func (b *backoff) fail(ip netip.Addr) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now, k := b.now(), backoffKey(ip)
	f := b.fails[k]
	if f != nil && now.Sub(f.last) >= backoffForget {
		f = nil
	}
	if f == nil {
		if len(b.fails) >= maxBackoffKeys {
			for key, old := range b.fails {
				if now.Sub(old.last) >= backoffForget {
					delete(b.fails, key)
				}
			}
			if len(b.fails) >= maxBackoffKeys {
				return false
			}
		}
		f = &failState{}
		b.fails[k] = f
	}
	f.n++
	f.last = now
	f.until = now.Add(min(backoffBase<<min(f.n-1, 16), backoffMax))
	return f.n == 1
}

// ok clears ip after a right token.
func (b *backoff) ok(ip netip.Addr) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.fails, backoffKey(ip))
}
