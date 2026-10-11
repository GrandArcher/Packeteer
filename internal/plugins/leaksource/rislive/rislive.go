// Package rislive is a leak source that reads RIPE RIS Live
// (https://ris-live.ripe.net) over its HTTP stream. The subscription asks
// for UPDATE announcements with the local ASN in the path, so the service
// sends only routes that crossed the operator's AS. It is read-only: the
// only request is the GET that opens the stream. A dropped stream is
// retried with a doubling delay, and while it is down the source reports
// itself unhealthy, which the leak watch shows as unknown.
package rislive

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Defaults and bounds.
const (
	// DefaultURL is the public RIS Live stream endpoint.
	DefaultURL     = "https://ris-live.ripe.net/v1/stream/"
	DefaultClient  = "packeteer-leak-watch"
	maxLine        = 1 << 20
	minRetry       = 5 * time.Second
	maxRetry       = 5 * time.Minute
	connectTimeout = 30 * time.Second
	// defaultIdle is how long the stream may stay silent before it is
	// treated as stalled. RIS Live sends no keepalive on this endpoint, so
	// a quiet filter and a dead connection look alike; reconnecting is cheap.
	defaultIdle = 15 * time.Minute
)

// Config is the plugin config.
type Config struct {
	// URL is the stream endpoint (default the public RIS Live service).
	URL string `yaml:"url"`
	// Client names this client to the service (default
	// "packeteer-leak-watch"). RIPE asks clients to identify themselves.
	Client string `yaml:"client"`
}

// Source is the plugin.
type Source struct {
	stream  string
	asn     uint32
	log     *slog.Logger
	retry   time.Duration
	idle    time.Duration
	healthy atomic.Bool

	mu     sync.Mutex
	sink   func(plugin.LeakSighting)
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func init() {
	plugin.LeakSources.Register("rislive", New)
}

// New validates the config. It does not connect.
func New(c plugin.Config, env plugin.Env) (plugin.LeakSource, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.URL == "" {
		cfg.URL = DefaultURL
	}
	if cfg.Client == "" {
		cfg.Client = DefaultClient
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("rislive: url %q: want an http or https URL", cfg.URL)
	}
	if u.RawQuery != "" {
		return nil, fmt.Errorf("rislive: url %q: leave the query out; format and client are added", cfg.URL)
	}
	if env.ASN == 0 {
		return nil, errors.New("rislive: needs the local asn to filter the stream")
	}
	q := url.Values{"format": {"json"}, "client": {cfg.Client}}
	u.RawQuery = q.Encode()
	log := env.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Source{stream: u.String(), asn: env.ASN, log: log, retry: minRetry, idle: defaultIdle}, nil
}

// SetLeakSink implements plugin.LeakSource.
func (s *Source) SetLeakSink(fn func(plugin.LeakSighting)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sink = fn
}

// Healthy is true while the stream is open.
func (s *Source) Healthy() bool { return s.healthy.Load() }

// Start opens the stream in the background.
func (s *Source) Start(ctx context.Context) error {
	run, cancel := context.WithCancel(context.WithoutCancel(ctx))
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.loop(run)
	}()
	return nil
}

// Stop closes the stream.
func (s *Source) Stop(ctx context.Context) error {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Source) loop(ctx context.Context) {
	delay := s.retry
	for ctx.Err() == nil {
		connected, err := s.read(ctx)
		s.healthy.Store(false)
		if ctx.Err() != nil {
			return
		}
		if connected {
			delay = s.retry
		}
		s.log.Warn("ris live stream ended; retrying", "err", err, "in", delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, maxRetry)
	}
}

// subscription is the X-RIS-Subscribe header: announcements whose AS path
// contains the local ASN.
func (s *Source) subscription() string {
	b, _ := json.Marshal(map[string]any{"type": "UPDATE", "require": "announcements", "path": s.asn})
	return string(b)
}

// read streams until the connection ends. connected is true once the
// service answered 200.
func (s *Source) read(ctx context.Context) (connected bool, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.stream, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-RIS-Subscribe", s.subscription())
	hc := &http.Client{Transport: &http.Transport{ResponseHeaderTimeout: connectTimeout, TLSHandshakeTimeout: connectTimeout}}
	defer hc.CloseIdleConnections()
	resp, err := hc.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("ris live answered %s", resp.Status)
	}
	s.healthy.Store(true)
	s.log.Info("ris live stream open", "asn", s.asn)
	// A stalled stream stays open but silent; cutting it off turns
	// Healthy false, so the watch reports unknown instead of watching.
	stall := time.AfterFunc(s.idle, cancel)
	defer stall.Stop()
	br := bufio.NewReaderSize(resp.Body, 64<<10)
	for {
		line, err := readLine(br)
		stall.Reset(s.idle)
		if len(line) > 0 {
			s.handle(line)
		}
		if err != nil {
			return true, err
		}
	}
}

// readLine reads one line of at most maxLine bytes.
func readLine(br *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > maxLine {
			return nil, errors.New("ris live: line too long")
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return bytes.TrimSpace(line), err
	}
}

type envelope struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type update struct {
	Peer          string      `json:"peer"`
	Host          string      `json:"host"`
	Type          string      `json:"type"`
	Path          []pathElem  `json:"path"`
	Community     [][2]uint32 `json:"community"`
	Announcements []struct {
		Prefixes []string `json:"prefixes"`
	} `json:"announcements"`
}

// pathElem is one AS path entry: an ASN, or an AS_SET as an array.
type pathElem []uint32

func (p *pathElem) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '[' {
		return json.Unmarshal(b, (*[]uint32)(p))
	}
	var n uint32
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*p = pathElem{n}
	return nil
}

func (s *Source) handle(line []byte) {
	var env envelope
	if err := json.Unmarshal(line, &env); err != nil {
		s.log.Debug("ris live: unreadable line", "err", err)
		return
	}
	switch env.Type {
	case "ris_message":
	case "ris_error":
		s.log.Warn("ris live error", "data", string(env.Data))
		return
	default:
		return
	}
	var u update
	if err := json.Unmarshal(env.Data, &u); err != nil || u.Type != "UPDATE" {
		return
	}
	s.mu.Lock()
	fn := s.sink
	s.mu.Unlock()
	if fn == nil {
		return
	}
	var path []uint32
	for _, e := range u.Path {
		path = append(path, e...)
	}
	comms := make([]uint32, len(u.Community))
	for i, c := range u.Community {
		comms[i] = c[0]<<16 | c[1]
	}
	seen := u.Host + "/" + u.Peer
	for _, a := range u.Announcements {
		for _, ps := range a.Prefixes {
			p, err := netip.ParsePrefix(ps)
			if err != nil {
				continue
			}
			fn(plugin.LeakSighting{Prefix: p, ASPath: path, Communities: comms, Seen: seen})
		}
	}
}
