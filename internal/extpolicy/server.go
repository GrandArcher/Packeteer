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
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
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
	cert tls.Certificate
	hash [sha256.Size]byte
	grpc *grpc.Server
	srv  *http.Server
	ln   net.Listener
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
	s := &Server{feed: feed, log: log, cfg: cfg, cert: cert, hash: sha256.Sum256([]byte(cfg.Token))}
	s.grpc = grpc.NewServer()
	s.grpc.RegisterService(&serviceDesc, s)
	s.srv = &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}},
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	return s, nil
}

// Start listens and serves in the background.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("external_policy listen %s: %w", s.cfg.Listen, err)
	}
	s.ln = ln
	go func() {
		if err := s.srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
		if !s.authorized(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="packeteer"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
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
