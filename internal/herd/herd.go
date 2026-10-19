package herd

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// NewRules builds the sharing rules from the config. own are the
// operator's own and customer prefixes (inbound prefixes, flow transit
// customers, span local): nothing equal to, inside, or covering them is
// shared.
func NewRules(c *config.Herd, own []netip.Prefix) *Rules {
	r := &Rules{
		Prefixes: append(c.Share.Exclude.PrefixList(), own...),
		ASNs:     map[uint32]bool{},
		Sources:  map[string]bool{},
	}
	for _, a := range c.Share.Exclude.ASNs {
		r.ASNs[a] = true
	}
	for _, s := range c.Share.Sources {
		r.Sources[s] = true
	}
	return r
}

// Options builds a Herd.
type Options struct {
	Cfg   *config.Herd
	ASN   uint32
	Store plugin.HerdStore
	RIB   RIB
	Rules *Rules
	// Methods maps prober names to icmp, tcp, or udp; FirstMethod labels a
	// failed round; SourceTypes maps target source names to their types.
	Methods     map[string]string
	FirstMethod string
	SourceTypes map[string]string
	Log         *slog.Logger
	// Event raises an operator event.
	Event func(msg string)
	// Audit receives each served records response.
	Audit func(Audit)
	// Active gates serving and pulling (HA: only the active node).
	Active func() bool
	Now    func() time.Time
}

// Herd is the whole feature on one node: recorder, pull API, puller. It
// shares nothing with the controller's critical paths. Offer is the only
// call on the probe loop's path and never blocks.
type Herd struct {
	o     Options
	node  *Node
	trips *Trips
	rec   *Recorder
	srv   *Server
	pull  *Puller

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// New loads (or creates) the node key and builds the parts. It opens no
// socket and starts nothing.
func New(o Options) (*Herd, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	node, err := LoadNode(o.Cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	h := &Herd{o: o, node: node, trips: &Trips{}}
	h.rec = NewRecorder(RecorderOptions{
		Cfg: o.Cfg, Node: node, Store: o.Store, RIB: o.RIB, Rules: o.Rules, Methods: o.Methods,
		FirstMethod: o.FirstMethod, SourceTypes: o.SourceTypes, Now: o.Now, Log: o.Log, Event: o.Event,
	})
	keys, err := PinnedKeys(o.Cfg)
	if err != nil {
		return nil, err
	}
	h.srv = NewServer(ServerOptions{
		Cfg: o.Cfg, ASN: o.ASN, Node: node, Store: o.Store, Rules: o.Rules, Peers: keys, Now: o.Now,
		Log: o.Log, Trips: h.trips, Active: o.Active, Audit: o.Audit,
	})
	if o.Cfg.Serving() {
		if h.pull, err = NewPuller(PullerOptions{
			Cfg: o.Cfg, Node: node, Store: o.Store, Origins: h.rec.Origins, Now: o.Now, Log: o.Log,
			Trips: h.trips, Event: o.Event, Active: o.Active,
		}); err != nil {
			return nil, err
		}
	}
	return h, nil
}

// Offer hands a probe round to herd. It never blocks.
func (h *Herd) Offer(batch []probe.Result) { h.rec.Offer(batch) }

// Start opens the pull API and starts recording and pulling. A node in
// preview_only mode records and previews but listens and pulls nothing.
func (h *Herd) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cancel != nil {
		return errors.New("herd already started")
	}
	if h.o.Cfg.Serving() {
		if err := h.srv.Start(); err != nil {
			return err
		}
	}
	ctx, h.cancel = context.WithCancel(ctx)
	h.done = make(chan struct{})
	var wg sync.WaitGroup
	run := func(f func(context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx) }()
	}
	run(h.rec.Run)
	if h.pull != nil {
		run(h.pull.Run)
	}
	go func() { wg.Wait(); close(h.done) }()
	h.o.Log.Info("herd on", "key", h.node.ID(), "granularity", h.o.Cfg.Share.Granularity, "serving", h.o.Cfg.Serving())
	return nil
}

// Stop closes the listener and stops herd work. Herd holds nothing the
// controller needs to withdraw.
func (h *Herd) Stop(ctx context.Context) {
	h.mu.Lock()
	cancel, done := h.cancel, h.done
	h.cancel = nil
	h.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	h.srv.Stop()
	if h.pull != nil {
		h.pull.Close()
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// Preview is the signed response a puller would receive for raw, from the
// same code that serves real pulls.
func (h *Herd) Preview(raw string) (int, []byte) { return h.srv.Preview(raw) }

// PreviewStatus is the signed status document a puller would receive.
func (h *Herd) PreviewStatus() []byte {
	b, _ := h.srv.Status()
	return b
}

// Vantages is the per-vantage view of own and pulled records.
func (h *Herd) Vantages(ctx context.Context, raw string) (VantageView, error) {
	peers := map[string]uint32{}
	if h.pull != nil {
		for _, p := range h.pull.Peers() {
			peers[p.KeyID] = p.ASN
		}
	}
	return BuildView(ctx, h.o.Store, raw, h.o.ASN, peers, h.o.Now())
}

// NodeStatus is what the status API reports.
type NodeStatus struct {
	Enabled       bool         `json:"enabled"`
	PreviewOnly   bool         `json:"preview_only"`
	Serving       bool         `json:"serving"`
	KeyID         string       `json:"key_id"`
	PublicKey     string       `json:"public_key"`
	ASN           uint32       `json:"asn"`
	Country       string       `json:"country"`
	Granularity   string       `json:"granularity"`
	Classes       []string     `json:"classes"`
	Sources       []string     `json:"sources"`
	Discovery     string       `json:"discovery"`
	RetentionDays int          `json:"retention_days"`
	Peers         []PeerStatus `json:"peers"`
	Limits        []TripCount  `json:"limit_trips"`
	Queue         QueueStatus  `json:"queue"`
	Store         StoreStatus  `json:"store"`
}

// QueueStatus is the recorder's hand-off queue.
type QueueStatus struct {
	Dropped  uint64 `json:"dropped"`
	Stored   uint64 `json:"stored"`
	Restarts uint64 `json:"restarts"`
}

// StoreStatus is what the herd tables hold and their budgets.
type StoreStatus struct {
	LocalRecords  int   `json:"local_records"`
	LocalBytes    int64 `json:"local_bytes"`
	LocalBudget   int64 `json:"local_budget_bytes"`
	PulledRecords int   `json:"pulled_records"`
	PulledBytes   int64 `json:"pulled_bytes"`
	PulledBudget  int64 `json:"pulled_budget_bytes"`
}

// Status reports the node for the status API.
func (h *Herd) Status(ctx context.Context) NodeStatus {
	c := h.o.Cfg
	st := NodeStatus{
		Enabled: true, PreviewOnly: c.PreviewOnly, Serving: c.Serving(), KeyID: h.node.ID(), PublicKey: h.node.PublicKey(),
		ASN: h.o.ASN, Country: c.Vantage.Country, Granularity: c.Share.Granularity, Classes: c.Share.Classes,
		Sources: c.Share.Sources, Discovery: c.Share.Discovery, RetentionDays: c.RetentionDays,
		Peers: []PeerStatus{}, Limits: h.trips.Snapshot(),
		Queue: QueueStatus{Dropped: h.rec.Dropped(), Stored: h.rec.Stored(), Restarts: h.rec.Restarts()},
	}
	if h.pull != nil {
		st.Peers = h.pull.Peers()
		st.Queue.Restarts += h.pull.Restarts()
	}
	if s, err := h.o.Store.HerdStats(ctx); err == nil {
		st.Store = StoreStatus{
			LocalRecords: s.LocalRecords, LocalBytes: s.LocalBytes, LocalBudget: c.Limits.LocalBytes,
			PulledRecords: s.PulledRecords, PulledBytes: s.PulledBytes, PulledBudget: c.Limits.PulledBytes,
		}
	}
	return st
}
