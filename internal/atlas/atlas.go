// Package atlas is the opt-in RIPE Atlas integration (#213). With the
// operator's own API key it creates one-off ping or traceroute
// measurements toward a prefix's test address from a configured probe set,
// on demand or once after a move, and keeps the parsed results for display
// beside the local measurements. It also reads the status of the
// operator's own hosted probe and the credit balance.
//
// Results are display and evidence only. They never reach Decide, scoring,
// or any announcer, and nothing here moves a route. Spending is bounded by
// two hard caps (credits per day, measurements per hour) kept in a ledger
// that survives restarts. The key comes from KeyEnv, is sent only in the
// Authorization header, and is never logged or returned.
package atlas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/linkout"
)

// Measurement types and what started them.
const (
	TypePing       = "ping"
	TypeTraceroute = "traceroute"
	TriggerManual  = "manual"
	TriggerMove    = "after_move"
)

// Record states.
const (
	RecordPending = "pending"
	RecordDone    = "done"
	// RecordExpired is a measurement that did not finish inside resultWait.
	// It keeps the results that did arrive.
	RecordExpired = "expired"
)

// States of the integration.
const (
	StateOff   = "off"
	StateNoKey = "no_key"
	StateOK    = "ok"
)

const (
	timeout   = 20 * time.Second
	maxBody   = 4 << 20
	tickEvery = 15 * time.Second
	// resultWait is how long a measurement is polled before it is closed
	// with the results it has.
	resultWait = 10 * time.Minute
	// statusEvery is how often probe status and credit balance are read.
	statusEvery = 5 * time.Minute
	maxRecords  = 200
	maxQueued   = 64
	// Packet counts and sizes are sent explicitly so the credit estimate
	// matches what Atlas bills.
	pingPackets  = 3
	pingSize     = 48
	tracePackets = 3
	traceSize    = 40
	// Credits per result for a one-off measurement: the unit cost
	// N*(int(size/1500)+1) for ping and 10*N*(int(size/1500)+1) for
	// traceroute, doubled for one-off (Atlas credits documentation).
	pingCredits  = 2 * pingPackets * (pingSize/1500 + 1)
	traceCredits = 2 * 10 * tracePackets * (traceSize/1500 + 1)
)

// Errors a caller turns into a status code.
var (
	ErrOff       = errors.New("RIPE Atlas measurements are not enabled")
	ErrNoKey     = errors.New(KeyEnv + " is not set")
	ErrPublic    = errors.New("only public addresses are sent to RIPE Atlas")
	ErrBadType   = errors.New("measurement type must be ping or traceroute")
	ErrCapCredit = errors.New("the daily credit cap is reached")
	ErrCapHour   = errors.New("the hourly measurement cap is reached")
	ErrBalance   = errors.New("the Atlas credit balance is too low")
)

// Request is one measurement to create.
type Request struct {
	Prefix  netip.Prefix
	Target  netip.Addr
	Type    string
	Trigger string
	// Provider is the provider traffic moved to, for an after-move request.
	Provider string
}

// ProbeResult is one Atlas probe's answer. No probe or hop address is kept.
type ProbeResult struct {
	Probe int  `json:"probe"`
	Own   bool `json:"own,omitempty"`
	// Reached is true when the destination answered.
	Reached  bool    `json:"reached"`
	Sent     int     `json:"sent,omitempty"`
	Received int     `json:"received,omitempty"`
	RTTMs    float64 `json:"rtt_ms,omitempty"`
	Hops     int     `json:"hops,omitempty"`
}

// Summary condenses the probe answers.
type Summary struct {
	Answered int `json:"answered"`
	Reached  int `json:"reached"`
	// MedianRTTMs is over the probes that reached the destination.
	MedianRTTMs float64 `json:"median_rtt_ms,omitempty"`
	// LossPct is over ping packets and is absent for traceroute.
	LossPct *float64 `json:"loss_pct,omitempty"`
}

// Record is one created measurement and what came back.
type Record struct {
	ID        int           `json:"id"`
	Prefix    string        `json:"prefix"`
	Target    string        `json:"target"`
	Type      string        `json:"type"`
	Trigger   string        `json:"trigger"`
	Provider  string        `json:"provider,omitempty"`
	Created   time.Time     `json:"created"`
	Credits   int           `json:"credits"`
	Requested int           `json:"requested"`
	State     string        `json:"state"`
	Probes    []ProbeResult `json:"probes,omitempty"`
	Summary   *Summary      `json:"summary,omitempty"`
}

type spend struct {
	T       time.Time `json:"t"`
	Credits int       `json:"credits"`
}

type stateFile struct {
	Spends  []spend  `json:"spends"`
	Records []Record `json:"records"`
}

// ProbeStatus is the operator's own probe as Atlas reports it.
type ProbeStatus struct {
	Status string    `json:"status"`
	Since  time.Time `json:"since,omitzero"`
}

// Status is what the System page and the API show.
type Status struct {
	State   string `json:"state"`
	ProbeID int    `json:"probe_id,omitempty"`
	// ProbeURL links to the probe's page on atlas.ripe.net.
	ProbeURL string       `json:"probe_url,omitempty"`
	Probe    *ProbeStatus `json:"probe,omitempty"`
	// Balance is the credit balance, nil until read.
	Balance *int `json:"balance,omitempty"`
	// Error is the last failed read of status or balance.
	Error                  string    `json:"error,omitempty"`
	Checked                time.Time `json:"checked,omitzero"`
	CreditsToday           int       `json:"credits_today"`
	MaxCreditsPerDay       int       `json:"max_credits_per_day"`
	MeasurementsLastHour   int       `json:"measurements_last_hour"`
	MaxMeasurementsPerHour int       `json:"max_measurements_per_hour"`
}

type queued struct {
	req Request
	due time.Time
}

// Client talks to Atlas. A nil Client is off. Safe for concurrent use.
type Client struct {
	cfg  Config
	key  string
	ua   string
	http *http.Client
	log  *slog.Logger
	now  func() time.Time

	createMu sync.Mutex // serializes create so the caps cannot race

	mu      sync.Mutex
	spends  []spend
	records []Record
	queue   []queued
	probe   *ProbeStatus
	balance *int
	statErr string
	checked time.Time
	nextTry time.Time
}

// New builds a client from a validated block. key is the value of KeyEnv;
// version goes in the User-Agent. A disabled block, or an empty key, gives
// a client that makes no request.
func New(cfg Config, key, version string, log *slog.Logger) *Client {
	cfg = cfg.WithDefaults()
	if log == nil {
		log = slog.Default()
	}
	c := &Client{
		cfg: cfg,
		key: strings.TrimSpace(key),
		ua:  "Packeteer/" + version + " (+https://github.com/GrandArcher/Packeteer)",
		http: &http.Client{
			Timeout:       timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		log: log,
		now: time.Now,
	}
	if cfg.Enabled && c.key == "" {
		log.Warn("atlas: enabled but "+KeyEnv+" is not set; no Atlas request will be made", "state", StateNoKey)
	}
	if c.Active() {
		c.load()
	}
	return c
}

// Active reports whether requests can be made: enabled and a key is set.
func (c *Client) Active() bool { return c != nil && c.cfg.Enabled && c.key != "" }

// State is off, no_key, or ok.
func (c *Client) State() string {
	switch {
	case c == nil || !c.cfg.Enabled:
		return StateOff
	case c.key == "":
		return StateNoKey
	}
	return StateOK
}

func (c *Client) load() {
	b, err := os.ReadFile(c.cfg.StateFile)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			c.log.Warn("atlas: state file unreadable, starting with an empty ledger", "path", c.cfg.StateFile, "err", err)
		}
		return
	}
	var st stateFile
	if err := json.Unmarshal(b, &st); err != nil {
		c.log.Warn("atlas: state file is not valid, starting with an empty ledger", "path", c.cfg.StateFile, "err", err)
		return
	}
	c.spends, c.records = st.Spends, st.Records
	c.pruneSpends()
}

// save writes the ledger and records. Callers hold c.mu.
func (c *Client) save() {
	b, err := json.Marshal(stateFile{Spends: c.spends, Records: c.records})
	if err == nil {
		tmp := c.cfg.StateFile + ".tmp"
		if err = os.MkdirAll(filepath.Dir(c.cfg.StateFile), 0o700); err == nil {
			if err = os.WriteFile(tmp, b, 0o600); err == nil {
				err = os.Rename(tmp, c.cfg.StateFile)
			}
		}
	}
	if err != nil {
		c.log.Warn("atlas: state not saved; the caps hold only until a restart", "path", c.cfg.StateFile, "err", err)
	}
}

// pruneSpends drops ledger entries older than a day. Callers hold c.mu.
func (c *Client) pruneSpends() {
	cut := c.now().Add(-24 * time.Hour)
	c.spends = slices.DeleteFunc(c.spends, func(s spend) bool { return s.T.Before(cut) })
}

func (c *Client) usage() (credits, lastHour int) {
	c.pruneSpends()
	hour := c.now().Add(-time.Hour)
	for _, s := range c.spends {
		credits += s.Credits
		if s.T.After(hour) {
			lastHour++
		}
	}
	return credits, lastHour
}

// Estimate is the credits a one-off measurement of the given type from n
// probes costs.
func Estimate(typ string, n int) int {
	if typ == TypeTraceroute {
		return traceCredits * n
	}
	return pingCredits * n
}

type probeSpec struct {
	Requested int    `json:"requested"`
	Type      string `json:"type"`
	Value     string `json:"value"`
}

type definition struct {
	Target      string `json:"target"`
	Description string `json:"description"`
	Type        string `json:"type"`
	AF          int    `json:"af"`
	Packets     int    `json:"packets"`
	Size        int    `json:"size"`
	Protocol    string `json:"protocol,omitempty"`
}

// notRoutable is IPv4 space that is never a measurable public host and that
// linkout.InternalAddr does not cover.
var notRoutable = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// PublicTarget reports whether a is an address that may be sent to Atlas:
// not private, shared (CGNAT), loopback, link-local, unspecified, reserved,
// or multicast.
func PublicTarget(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || linkout.InternalAddr(a) || a.IsMulticast() {
		return false
	}
	return !slices.ContainsFunc(notRoutable, func(p netip.Prefix) bool { return p.Contains(a) })
}

// LocalRow is one provider's local measurement of a prefix, as far as the
// choice of Atlas target needs it.
type LocalRow struct {
	Provider string
	Target   netip.Addr
	Answered bool
}

// TestAddr picks the address Atlas probes are pointed at for a prefix: the
// target of prefer's row when it has one, else of the first row that
// answered, else of the first row with a target. Providers can measure
// different hosts of a prefix, so every record keeps the target it used.
func TestAddr(rows []LocalRow, prefer string) (netip.Addr, bool) {
	var answered, first netip.Addr
	for _, r := range rows {
		if !r.Target.IsValid() {
			continue
		}
		if prefer != "" && r.Provider == prefer {
			return r.Target, true
		}
		if !first.IsValid() {
			first = r.Target
		}
		if r.Answered && !answered.IsValid() {
			answered = r.Target
		}
	}
	if answered.IsValid() {
		return answered, true
	}
	return first, first.IsValid()
}

// Measure creates one measurement. It refuses before any request when the
// integration is off, the target is not public, or a cap or the known
// balance would be exceeded.
func (c *Client) Measure(ctx context.Context, req Request) (Record, error) {
	switch c.State() {
	case StateOff:
		return Record{}, ErrOff
	case StateNoKey:
		return Record{}, ErrNoKey
	}
	if req.Type != TypePing && req.Type != TypeTraceroute {
		return Record{}, ErrBadType
	}
	if !PublicTarget(req.Target) {
		return Record{}, ErrPublic
	}
	req.Target = req.Target.Unmap()
	c.createMu.Lock()
	defer c.createMu.Unlock()

	probes := []probeSpec{{Requested: c.cfg.Probes, Type: c.cfg.Source.Type, Value: c.cfg.Source.Value}}
	requested := c.cfg.Probes
	c.mu.Lock()
	if c.cfg.ProbeID > 0 && c.probe != nil && c.probe.Status == "Connected" {
		probes = append(probes, probeSpec{Requested: 1, Type: "probes", Value: strconv.Itoa(c.cfg.ProbeID)})
		requested++
	}
	cost := Estimate(req.Type, requested)
	today, lastHour := c.usage()
	var capErr error
	switch {
	case lastHour >= c.cfg.MaxMeasurementsPerHour:
		capErr = fmt.Errorf("%w (%d in the last hour)", ErrCapHour, lastHour)
	case today+cost > c.cfg.MaxCreditsPerDay:
		capErr = fmt.Errorf("%w (%d of %d credits booked, this needs about %d)", ErrCapCredit, today, c.cfg.MaxCreditsPerDay, cost)
	case c.balance != nil && *c.balance < cost:
		capErr = fmt.Errorf("%w (%d credits, this needs about %d)", ErrBalance, *c.balance, cost)
	}
	var booked spend
	if capErr == nil {
		// Booked before the request: a create that Atlas accepted but whose
		// answer was lost (timeout, closed tab) still counts against the caps.
		booked = spend{T: c.now().UTC(), Credits: cost}
		c.spends = append(c.spends, booked)
		c.save()
	}
	c.mu.Unlock()
	if capErr != nil {
		return Record{}, capErr
	}

	def := definition{Target: req.Target.String(), Description: "Packeteer " + req.Type + " " + req.Prefix.String(), Type: req.Type, AF: 4,
		Packets: pingPackets, Size: pingSize}
	if req.Target.Is6() {
		def.AF = 6
	}
	if req.Type == TypeTraceroute {
		def.Packets, def.Size, def.Protocol = tracePackets, traceSize, "ICMP"
	}
	body := map[string]any{"definitions": []definition{def}, "probes": probes, "is_oneoff": true}
	var out struct {
		Measurements []int `json:"measurements"`
	}
	// The request outlives a client that went away, so a created measurement
	// is always recorded; do() still bounds it with its own timeout.
	if err := c.do(context.WithoutCancel(ctx), http.MethodPost, "/measurements/", body, &out); err != nil {
		var se *statusError
		if errors.As(err, &se) && se.Status/100 == 4 {
			c.mu.Lock()
			if i := slices.Index(c.spends, booked); i >= 0 {
				c.spends = slices.Delete(c.spends, i, i+1)
				c.save()
			}
			c.mu.Unlock()
		}
		return Record{}, err
	}
	if len(out.Measurements) != 1 {
		return Record{}, errors.New("atlas: the measurement was created but no id came back")
	}
	rec := Record{ID: out.Measurements[0], Prefix: req.Prefix.String(), Target: req.Target.String(), Type: req.Type, Trigger: req.Trigger,
		Provider: req.Provider, Created: booked.T, Credits: cost, Requested: requested, State: RecordPending}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, rec)
	if len(c.records) > maxRecords {
		c.records = c.records[len(c.records)-maxRecords:]
	}
	c.save()
	return rec, nil
}

// AfterMove queues one measurement of the destination of a move, due after
// the configured delay. Off unless after_move is set. A newer move for the
// same prefix replaces the queued one.
func (c *Client) AfterMove(prefix netip.Prefix, target netip.Addr, provider string) {
	if !c.Active() || !c.cfg.AfterMove {
		return
	}
	q := queued{req: Request{Prefix: prefix, Target: target, Type: TypePing, Trigger: TriggerMove, Provider: provider}, due: c.now().Add(c.cfg.AfterMoveDelay)}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.queue = slices.DeleteFunc(c.queue, func(o queued) bool { return o.req.Prefix == prefix })
	if len(c.queue) >= maxQueued {
		c.log.Debug("atlas: after-move queue full, measurement skipped", "prefix", prefix)
		return
	}
	c.queue = append(c.queue, q)
}

// Run drives queued after-move measurements, result polling, and the
// probe and balance reads until ctx ends.
func (c *Client) Run(ctx context.Context) {
	if !c.Active() {
		return
	}
	t := time.NewTicker(tickEvery)
	defer t.Stop()
	for {
		c.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (c *Client) tick(ctx context.Context) {
	c.refreshStatus(ctx)
	c.mu.Lock()
	now := c.now()
	var due []queued
	c.queue = slices.DeleteFunc(c.queue, func(q queued) bool {
		if q.due.After(now) {
			return false
		}
		due = append(due, q)
		return true
	})
	c.mu.Unlock()
	for _, q := range due {
		if _, err := c.Measure(ctx, q.req); err != nil {
			c.log.Info("atlas: after-move measurement not made", "prefix", q.req.Prefix, "err", err)
		}
	}
	c.pollPending(ctx)
}

type atlasResult struct {
	Type      string  `json:"type"`
	ProbeID   int     `json:"prb_id"`
	Sent      int     `json:"sent"`
	Rcvd      int     `json:"rcvd"`
	Avg       float64 `json:"avg"`
	Responded bool    `json:"destination_ip_responded"`
	Hops      []struct {
		Result []struct {
			RTT float64 `json:"rtt"`
		} `json:"result"`
	} `json:"result"`
}

func (c *Client) pollPending(ctx context.Context) {
	c.mu.Lock()
	var pending []Record
	for _, r := range c.records {
		if r.State == RecordPending {
			pending = append(pending, r)
		}
	}
	c.mu.Unlock()
	for _, r := range pending {
		var raw []json.RawMessage
		if err := c.do(ctx, http.MethodGet, "/measurements/"+strconv.Itoa(r.ID)+"/results/", nil, &raw); err != nil {
			c.log.Info("atlas: results not read", "measurement", r.ID, "err", err)
		} else {
			r.Probes = c.parse(r.Type, raw)
			r.Summary = summarize(r.Type, r.Probes)
		}
		switch {
		case len(r.Probes) >= r.Requested:
			r.State = RecordDone
		case c.now().Sub(r.Created) > resultWait:
			r.State = RecordExpired
		}
		c.mu.Lock()
		for i := range c.records {
			if c.records[i].ID == r.ID {
				c.records[i] = r
			}
		}
		c.save()
		c.mu.Unlock()
	}
}

func (c *Client) parse(typ string, raw []json.RawMessage) []ProbeResult {
	var out []ProbeResult
	for _, m := range raw {
		var a atlasResult
		if json.Unmarshal(m, &a) != nil || a.Type != typ {
			continue
		}
		p := ProbeResult{Probe: a.ProbeID, Own: c.cfg.ProbeID > 0 && a.ProbeID == c.cfg.ProbeID}
		if typ == TypePing {
			p.Sent, p.Received = a.Sent, a.Rcvd
			p.Reached = a.Rcvd > 0
			if p.Reached {
				p.RTTMs = a.Avg
			}
		} else {
			p.Hops = len(a.Hops)
			p.Reached = a.Responded
			if n := len(a.Hops); n > 0 && p.Reached {
				var sum float64
				var k int
				for _, h := range a.Hops[n-1].Result {
					if h.RTT > 0 {
						sum += h.RTT
						k++
					}
				}
				if k > 0 {
					p.RTTMs = sum / float64(k)
				}
			}
		}
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b ProbeResult) int { return a.Probe - b.Probe })
	return out
}

func summarize(typ string, probes []ProbeResult) *Summary {
	s := &Summary{Answered: len(probes)}
	var rtts []float64
	var sent, rcvd int
	for _, p := range probes {
		sent += p.Sent
		rcvd += p.Received
		if p.Reached {
			s.Reached++
			if p.RTTMs > 0 {
				rtts = append(rtts, p.RTTMs)
			}
		}
	}
	slices.Sort(rtts)
	if n := len(rtts); n > 0 {
		s.MedianRTTMs = rtts[n/2]
		if n%2 == 0 {
			s.MedianRTTMs = (rtts[n/2-1] + rtts[n/2]) / 2
		}
	}
	if typ == TypePing && sent > 0 {
		loss := 100 * float64(sent-rcvd) / float64(sent)
		s.LossPct = &loss
	}
	return s
}

// refreshStatus reads the own probe and the credit balance, at most every
// statusEvery. A failed read is retried after a minute.
func (c *Client) refreshStatus(ctx context.Context) {
	c.mu.Lock()
	if c.now().Before(c.nextTry) {
		c.mu.Unlock()
		return
	}
	c.nextTry = c.now().Add(statusEvery)
	c.mu.Unlock()

	var errs []string
	var probe *ProbeStatus
	if c.cfg.ProbeID > 0 {
		var p struct {
			Status struct {
				Name  string `json:"name"`
				Since string `json:"since"`
			} `json:"status"`
		}
		if err := c.do(ctx, http.MethodGet, "/probes/"+strconv.Itoa(c.cfg.ProbeID)+"/", nil, &p); err != nil {
			errs = append(errs, "probe: "+err.Error())
		} else {
			probe = &ProbeStatus{Status: p.Status.Name}
			probe.Since, _ = time.Parse(time.RFC3339, p.Status.Since)
		}
	}
	var cr struct {
		Balance *int `json:"current_balance"`
	}
	if err := c.do(ctx, http.MethodGet, "/credits/", nil, &cr); err != nil {
		errs = append(errs, "credits: "+err.Error())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checked = c.now().UTC()
	c.statErr = strings.Join(errs, "; ")
	if len(errs) > 0 {
		c.nextTry = c.now().Add(time.Minute)
		c.log.Warn("atlas: status read failed", "err", c.statErr)
	}
	if probe != nil {
		c.probe = probe
	}
	if cr.Balance != nil {
		c.balance = cr.Balance
	}
}

// Status returns the integration's state, own probe, balance, and cap use.
func (c *Client) Status() Status {
	st := Status{State: c.State()}
	if c == nil {
		return st
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st.MaxCreditsPerDay, st.MaxMeasurementsPerHour = c.cfg.MaxCreditsPerDay, c.cfg.MaxMeasurementsPerHour
	if c.cfg.ProbeID > 0 {
		st.ProbeID = c.cfg.ProbeID
		st.ProbeURL = "https://atlas.ripe.net/probes/" + strconv.Itoa(c.cfg.ProbeID) + "/"
	}
	st.Probe, st.Balance, st.Error, st.Checked = c.probe, c.balance, c.statErr, c.checked
	st.CreditsToday, st.MeasurementsLastHour = c.usage()
	return st
}

// Records returns the measurements of a prefix, newest first.
func (c *Client) Records(prefix netip.Prefix) []Record {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Record
	for _, r := range slices.Backward(c.records) {
		if r.Prefix == prefix.String() {
			out = append(out, r)
		}
	}
	return out
}

// do sends one request. The key is set here and nowhere else; anything
// from the network that goes into an error is cleaned of it first.
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, body)
	if err != nil {
		return c.scrub(err)
	}
	req.Header.Set("Authorization", "Key "+c.key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return c.scrub(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return c.scrub(err)
	}
	if len(raw) > maxBody {
		return fmt.Errorf("atlas: %s answered over %d bytes", path, maxBody)
	}
	if res.StatusCode/100 != 2 {
		var e struct {
			Error struct {
				Detail string `json:"detail"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		return &statusError{Status: res.StatusCode, msg: c.scrub(fmt.Errorf("atlas: %s %s: HTTP %d %s", method, path, res.StatusCode, clip(e.Error.Detail))).Error()}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return errors.New("atlas: unreadable response from " + path)
	}
	return nil
}

// statusError is a non-2xx answer; a 4xx means Atlas created nothing.
type statusError struct {
	Status int
	msg    string
}

func (e *statusError) Error() string { return e.msg }

func (c *Client) scrub(err error) error {
	if err == nil || c.key == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), c.key, "***"))
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return strings.ToValidUTF8(s[:200], "")
	}
	return s
}
