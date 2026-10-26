package atlas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const testKey = "k3y-0000-fake-test-value"

// fakeAtlas is a stand-in for the Atlas REST API. It records what it was
// asked and answers from the fields below.
type fakeAtlas struct {
	mu       sync.Mutex
	creates  []map[string]any
	auth     []string
	nextID   int
	results  map[int]string
	probe    string
	balance  string
	failWith int
	// dropAnswer makes a create succeed on the server and then cut the
	// connection, as a timeout or a closed tab would.
	dropAnswer bool
}

func (f *fakeAtlas) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	if f.failWith != 0 {
		w.WriteHeader(f.failWith)
		_, _ = w.Write([]byte(`{"error":{"detail":"bad key ` + testKey + `"}}`))
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/measurements/":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.creates = append(f.creates, body)
		f.nextID++
		if f.dropAnswer {
			panic(http.ErrAbortHandler)
		}
		_, _ = w.Write([]byte(`{"measurements":[` + strconv.Itoa(1000+f.nextID) + `]}`))
	case strings.HasSuffix(r.URL.Path, "/results/"):
		id, _ := strconv.Atoi(strings.Split(r.URL.Path, "/")[2])
		res := f.results[id]
		if res == "" {
			res = "[]"
		}
		_, _ = w.Write([]byte(res))
	case strings.HasPrefix(r.URL.Path, "/probes/"):
		_, _ = w.Write([]byte(f.probe))
	case r.URL.Path == "/credits/":
		_, _ = w.Write([]byte(f.balance))
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeAtlas) created() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.creates)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type rig struct {
	t     *testing.T
	api   *fakeAtlas
	srv   *httptest.Server
	clk   *clock
	logs  *bytes.Buffer
	state string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	api := &fakeAtlas{probe: `{"status":{"name":"Connected","since":"2026-10-20T10:00:00Z"}}`, balance: `{"current_balance": 1000}`}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	return &rig{t: t, api: api, srv: srv, clk: &clock{t: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)},
		logs: &bytes.Buffer{}, state: filepath.Join(t.TempDir(), "atlas.json")}
}

func (r *rig) client(cfg Config, key string) *Client {
	r.t.Helper()
	cfg.Enabled = true
	cfg.BaseURL = r.srv.URL
	cfg.StateFile = r.state
	c := New(cfg, key, "test", slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	c.now = r.clk.now
	return c
}

var (
	pfx    = netip.MustParsePrefix("198.51.100.0/24")
	target = netip.MustParseAddr("198.51.100.7")
)

func manual() Request {
	return Request{Prefix: pfx, Target: target, Type: TypePing, Trigger: TriggerManual}
}

func TestMeasureCreatesOneOffPingWithTheKeyInTheHeader(t *testing.T) {
	r := newRig(t)
	c := r.client(Config{Probes: 5, Source: Source{Type: "country", Value: "DE"}}, testKey)
	rec, err := c.Measure(context.Background(), manual())
	if err != nil {
		t.Fatal(err)
	}
	if rec.ID != 1001 || rec.State != RecordPending || rec.Requested != 5 || rec.Credits != 30 {
		t.Errorf("record = %+v", rec)
	}
	if got := r.api.auth[0]; got != "Key "+testKey {
		t.Errorf("Authorization = %q", got)
	}
	body := r.api.creates[0]
	if body["is_oneoff"] != true {
		t.Errorf("is_oneoff = %v", body["is_oneoff"])
	}
	def := body["definitions"].([]any)[0].(map[string]any)
	if def["target"] != "198.51.100.7" || def["type"] != "ping" || def["af"] != float64(4) || def["packets"] != float64(3) {
		t.Errorf("definition = %v", def)
	}
	src := body["probes"].([]any)[0].(map[string]any)
	if src["type"] != "country" || src["value"] != "DE" || src["requested"] != float64(5) {
		t.Errorf("probes = %v", body["probes"])
	}
}

func TestMeasureRefusals(t *testing.T) {
	r := newRig(t)
	off := New(Config{}, testKey, "test", nil)
	if _, err := off.Measure(context.Background(), manual()); !errors.Is(err, ErrOff) {
		t.Errorf("off: %v", err)
	}
	noKey := r.client(Config{}, "  ")
	if _, err := noKey.Measure(context.Background(), manual()); !errors.Is(err, ErrNoKey) {
		t.Errorf("no key: %v", err)
	}
	if noKey.State() != StateNoKey || off.State() != StateOff {
		t.Errorf("states = %s, %s", noKey.State(), off.State())
	}
	c := r.client(Config{}, testKey)
	for _, a := range []string{"10.1.2.3", "127.0.0.1", "169.254.1.1", "fd00::1", "224.0.0.1", "::"} {
		req := manual()
		req.Target = netip.MustParseAddr(a)
		if _, err := c.Measure(context.Background(), req); !errors.Is(err, ErrPublic) {
			t.Errorf("%s: %v", a, err)
		}
	}
	req := manual()
	req.Type = "http"
	if _, err := c.Measure(context.Background(), req); !errors.Is(err, ErrBadType) {
		t.Errorf("type: %v", err)
	}
	if n := r.api.created() + len(r.api.auth); n != 0 {
		t.Errorf("%d requests reached Atlas", n)
	}
}

func TestHourlyCapAndItReleases(t *testing.T) {
	r := newRig(t)
	c := r.client(Config{MaxMeasurementsPerHour: 2, MaxCreditsPerDay: 1000}, testKey)
	for range 2 {
		if _, err := c.Measure(context.Background(), manual()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Measure(context.Background(), manual()); !errors.Is(err, ErrCapHour) {
		t.Fatalf("third: %v", err)
	}
	if r.api.created() != 2 {
		t.Errorf("created = %d, want 2", r.api.created())
	}
	r.clk.add(61 * time.Minute)
	if _, err := c.Measure(context.Background(), manual()); err != nil {
		t.Errorf("after the hour: %v", err)
	}
}

func TestLostAnswerStillCountsAgainstTheCaps(t *testing.T) {
	r := newRig(t)
	c := r.client(Config{MaxMeasurementsPerHour: 1, MaxCreditsPerDay: 1000}, testKey)
	r.api.dropAnswer = true
	if _, err := c.Measure(context.Background(), manual()); err == nil {
		t.Fatal("a cut connection must be an error")
	}
	r.api.dropAnswer = false
	if _, err := c.Measure(context.Background(), manual()); !errors.Is(err, ErrCapHour) {
		t.Fatalf("after the lost answer: %v", err)
	}
	if st := c.Status(); st.CreditsToday != 18 || st.MeasurementsLastHour != 1 {
		t.Errorf("status = %+v", st)
	}
	if got := r.client(Config{MaxMeasurementsPerHour: 1}, testKey).Status(); got.MeasurementsLastHour != 1 {
		t.Errorf("after a restart the booking is gone: %+v", got)
	}
}

func TestRefusedCreateReleasesItsBooking(t *testing.T) {
	r := newRig(t)
	c := r.client(Config{MaxMeasurementsPerHour: 1, MaxCreditsPerDay: 1000}, testKey)
	r.api.failWith = http.StatusForbidden
	if _, err := c.Measure(context.Background(), manual()); err == nil {
		t.Fatal("a 403 must be an error")
	}
	r.api.failWith = 0
	if _, err := c.Measure(context.Background(), manual()); err != nil {
		t.Fatalf("nothing was created, so the hour is still free: %v", err)
	}
	if st := c.Status(); st.CreditsToday != 18 || st.MeasurementsLastHour != 1 {
		t.Errorf("status = %+v", st)
	}
}

func TestDailyCreditCapSurvivesARestart(t *testing.T) {
	r := newRig(t)
	// 3 probes at 6 credits is 18; 40 credits allow two.
	cfg := Config{MaxCreditsPerDay: 40, MaxMeasurementsPerHour: 50}
	c := r.client(cfg, testKey)
	for range 2 {
		if _, err := c.Measure(context.Background(), manual()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Measure(context.Background(), manual()); !errors.Is(err, ErrCapCredit) {
		t.Fatalf("third: %v", err)
	}
	restarted := r.client(cfg, testKey)
	if _, err := restarted.Measure(context.Background(), manual()); !errors.Is(err, ErrCapCredit) {
		t.Fatalf("after restart: %v", err)
	}
	if st := restarted.Status(); st.CreditsToday != 36 || st.MeasurementsLastHour != 2 {
		t.Errorf("status = %+v", st)
	}
	if r.api.created() != 2 {
		t.Errorf("created = %d, want 2", r.api.created())
	}
	r.clk.add(25 * time.Hour)
	if _, err := restarted.Measure(context.Background(), manual()); err != nil {
		t.Errorf("after a day: %v", err)
	}
}

func TestTracerouteCostsTenTimesAPing(t *testing.T) {
	r := newRig(t)
	c := r.client(Config{MaxCreditsPerDay: 1000}, testKey)
	req := manual()
	req.Type = TypeTraceroute
	rec, err := c.Measure(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Credits != 180 {
		t.Errorf("credits = %d, want 180 (3 probes x 60)", rec.Credits)
	}
	def := r.api.creates[0]["definitions"].([]any)[0].(map[string]any)
	if def["type"] != "traceroute" || def["protocol"] != "ICMP" || def["size"] != float64(40) {
		t.Errorf("definition = %v", def)
	}
	small := r.client(Config{MaxCreditsPerDay: 100, MaxMeasurementsPerHour: 50}, testKey)
	if _, err := small.Measure(context.Background(), req); !errors.Is(err, ErrCapCredit) {
		t.Errorf("traceroute over a 100 credit cap: %v", err)
	}
}

func TestKeyNeverLoggedOrReturned(t *testing.T) {
	r := newRig(t)
	c := r.client(Config{ProbeID: 6001}, testKey)
	r.api.failWith = http.StatusForbidden
	_, err := c.Measure(context.Background(), manual())
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("err = %v", err)
	}
	c.tick(context.Background())
	r.api.failWith = 0
	if _, err := c.Measure(context.Background(), manual()); err != nil {
		t.Fatal(err)
	}
	r.api.results = map[int]string{1001: `[{"type":"ping","prb_id":7,"sent":3,"rcvd":3,"avg":10}]`}
	c.tick(context.Background())

	st, _ := json.Marshal(c.Status())
	recs, _ := json.Marshal(c.Records(pfx))
	file, _ := os.ReadFile(r.state)
	for name, got := range map[string]string{"error": err.Error(), "logs": r.logs.String(), "status": string(st), "records": string(recs), "state file": string(file)} {
		if strings.Contains(got, testKey) {
			t.Errorf("%s contains the key: %s", name, got)
		}
	}
	if !strings.Contains(r.logs.String(), "atlas: status read failed") {
		t.Errorf("the failed status read was not logged: %s", r.logs.String())
	}
}

func TestNoKeyMakesNoRequestAndWarnsOnce(t *testing.T) {
	r := newRig(t)
	c := r.client(Config{AfterMove: true}, "")
	c.AfterMove(pfx, target, "transit-b")
	c.Run(context.Background())
	if len(r.api.auth) != 0 {
		t.Errorf("%d requests with no key", len(r.api.auth))
	}
	if n := strings.Count(r.logs.String(), KeyEnv+" is not set"); n != 1 {
		t.Errorf("warning logged %d times", n)
	}
}

func TestResultsParsedPingAndTraceroute(t *testing.T) {
	r := newRig(t)
	c := r.client(Config{ProbeID: 6001, MaxCreditsPerDay: 1000, MaxMeasurementsPerHour: 10}, testKey)
	c.tick(context.Background())
	rec, err := c.Measure(context.Background(), manual())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Requested != 4 {
		t.Fatalf("requested = %d, want 3 + the own probe", rec.Requested)
	}
	r.api.results = map[int]string{rec.ID: `[
 {"type":"ping","prb_id":6001,"sent":3,"rcvd":3,"avg":12.0,"dst_addr":"198.51.100.7"},
 {"type":"ping","prb_id":7,"sent":3,"rcvd":2,"avg":30.0},
 {"type":"ping","prb_id":9,"sent":3,"rcvd":0,"avg":-1},
 {"type":"traceroute","prb_id":11}]`}
	c.tick(context.Background())
	got := c.Records(pfx)[0]
	if got.State != RecordPending || len(got.Probes) != 3 {
		t.Fatalf("one probe still missing: state %s, %d probes", got.State, len(got.Probes))
	}
	r.api.results[rec.ID] = strings.Replace(r.api.results[rec.ID], `{"type":"traceroute","prb_id":11}`, `{"type":"ping","prb_id":12,"sent":3,"rcvd":3,"avg":50.0}`, 1)
	c.tick(context.Background())
	got = c.Records(pfx)[0]
	if got.State != RecordDone || len(got.Probes) != 4 {
		t.Fatalf("record = %+v", got)
	}
	if p := got.Probes[0]; p.Probe != 7 || p.Own || !p.Reached || p.RTTMs != 30 || p.Sent != 3 || p.Received != 2 {
		t.Errorf("probe 7 = %+v", p)
	}
	if p := got.Probes[1]; p.Probe != 9 || p.Reached || p.RTTMs != 0 {
		t.Errorf("probe 9 = %+v", p)
	}
	if p := got.Probes[3]; p.Probe != 6001 || !p.Own {
		t.Errorf("own probe = %+v", p)
	}
	s := got.Summary
	// Reached: 7 (30), 12 (50), 6001 (12). Median 30. Lost 4 of 12.
	if s.Answered != 4 || s.Reached != 3 || s.MedianRTTMs != 30 || s.LossPct == nil || int(*s.LossPct+0.5) != 33 {
		t.Errorf("summary = %+v loss=%v", s, s.LossPct)
	}
}

func TestTracerouteResultParsed(t *testing.T) {
	r := newRig(t)
	c := r.client(Config{MaxCreditsPerDay: 1000, Probes: 2}, testKey)
	req := manual()
	req.Type = TypeTraceroute
	rec, err := c.Measure(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	r.api.results = map[int]string{rec.ID: `[
 {"type":"traceroute","prb_id":7,"destination_ip_responded":true,"result":[
   {"hop":1,"result":[{"from":"192.0.2.1","rtt":1.0}]},
   {"hop":2,"result":[{"x":"*"},{"from":"198.51.100.7","rtt":20.0},{"from":"198.51.100.7","rtt":22.0}]}]},
 {"type":"traceroute","prb_id":8,"destination_ip_responded":false,"result":[{"hop":1,"result":[{"x":"*"}]}]}]`}
	c.tick(context.Background())
	got := c.Records(pfx)[0]
	if got.State != RecordDone || len(got.Probes) != 2 {
		t.Fatalf("record = %+v", got)
	}
	if p := got.Probes[0]; !p.Reached || p.Hops != 2 || p.RTTMs != 21 {
		t.Errorf("probe 7 = %+v", p)
	}
	if p := got.Probes[1]; p.Reached || p.Hops != 1 {
		t.Errorf("probe 8 = %+v", p)
	}
	if s := got.Summary; s.Reached != 1 || s.MedianRTTMs != 21 || s.LossPct != nil {
		t.Errorf("summary = %+v", s)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "192.0.2.1") {
		t.Errorf("a hop address was kept: %s", raw)
	}
}

func TestPendingMeasurementExpiresWithPartialResults(t *testing.T) {
	r := newRig(t)
	c := r.client(Config{}, testKey)
	rec, err := c.Measure(context.Background(), manual())
	if err != nil {
		t.Fatal(err)
	}
	r.api.results = map[int]string{rec.ID: `[{"type":"ping","prb_id":7,"sent":3,"rcvd":3,"avg":10}]`}
	c.tick(context.Background())
	if got := c.Records(pfx)[0]; got.State != RecordPending {
		t.Fatalf("state = %s", got.State)
	}
	r.clk.add(resultWait + time.Second)
	c.tick(context.Background())
	if got := c.Records(pfx)[0]; got.State != RecordExpired || len(got.Probes) != 1 || got.Summary.Reached != 1 {
		t.Errorf("record = %+v", got)
	}
}

func TestOwnProbeJoinsOnlyWhenConnected(t *testing.T) {
	r := newRig(t)
	c := r.client(Config{ProbeID: 6001, MaxCreditsPerDay: 1000, MaxMeasurementsPerHour: 10}, testKey)
	// Status is not read yet, so the probe is not known to be connected.
	if _, err := c.Measure(context.Background(), manual()); err != nil {
		t.Fatal(err)
	}
	if n := len(r.api.creates[0]["probes"].([]any)); n != 1 {
		t.Errorf("probes before the first status read = %d, want 1", n)
	}
	c.tick(context.Background())
	st := c.Status()
	if st.Probe == nil || st.Probe.Status != "Connected" || !st.Probe.Since.Equal(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)) ||
		st.Balance == nil || *st.Balance != 1000 || st.ProbeURL != "https://atlas.ripe.net/probes/6001/" {
		t.Fatalf("status = %+v", st)
	}
	if _, err := c.Measure(context.Background(), manual()); err != nil {
		t.Fatal(err)
	}
	probes := r.api.creates[1]["probes"].([]any)
	own := probes[1].(map[string]any)
	if len(probes) != 2 || own["type"] != "probes" || own["value"] != "6001" || own["requested"] != float64(1) {
		t.Errorf("probes = %v", probes)
	}

	r.api.probe = `{"status":{"name":"Disconnected","since":"2026-10-25T11:00:00Z"}}`
	r.clk.add(10 * time.Minute)
	c.tick(context.Background())
	if _, err := c.Measure(context.Background(), manual()); err != nil {
		t.Fatal(err)
	}
	if n := len(r.api.creates[2]["probes"].([]any)); n != 1 {
		t.Errorf("probes with the own probe disconnected = %d, want 1", n)
	}
}

func TestLowBalanceRefuses(t *testing.T) {
	r := newRig(t)
	r.api.balance = `{"current_balance": 10}`
	c := r.client(Config{}, testKey)
	c.tick(context.Background())
	if _, err := c.Measure(context.Background(), manual()); !errors.Is(err, ErrBalance) {
		t.Errorf("err = %v", err)
	}
	if r.api.created() != 0 {
		t.Error("a measurement was created")
	}
}

func TestAfterMoveWaitsThenMeasuresOnce(t *testing.T) {
	r := newRig(t)
	c := r.client(Config{}, testKey)
	c.AfterMove(pfx, target, "transit-b")
	c.tick(context.Background())
	if r.api.created() != 0 {
		t.Fatal("measured before after_move is on")
	}
	c = r.client(Config{AfterMove: true, AfterMoveDelay: 2 * time.Minute}, testKey)
	c.AfterMove(pfx, target, "transit-a")
	c.AfterMove(pfx, target, "transit-b") // the later move replaces the queued one
	c.tick(context.Background())
	if r.api.created() != 0 {
		t.Fatal("measured before the delay")
	}
	r.clk.add(3 * time.Minute)
	c.tick(context.Background())
	c.tick(context.Background())
	if r.api.created() != 1 {
		t.Fatalf("created = %d, want 1", r.api.created())
	}
	rec := c.Records(pfx)[0]
	if rec.Trigger != TriggerMove || rec.Provider != "transit-b" || rec.Type != TypePing {
		t.Errorf("record = %+v", rec)
	}
}

func TestAfterMoveRespectsTheCaps(t *testing.T) {
	r := newRig(t)
	c := r.client(Config{AfterMove: true, MaxMeasurementsPerHour: 1}, testKey)
	if _, err := c.Measure(context.Background(), manual()); err != nil {
		t.Fatal(err)
	}
	c.AfterMove(pfx, target, "transit-b")
	r.clk.add(4 * time.Minute)
	c.tick(context.Background())
	if r.api.created() != 1 {
		t.Errorf("created = %d: the move measurement ignored the hourly cap", r.api.created())
	}
	if !strings.Contains(r.logs.String(), "after-move measurement not made") {
		t.Errorf("the refusal was not logged: %s", r.logs.String())
	}
}

func TestRecordsAreForOnePrefix(t *testing.T) {
	r := newRig(t)
	c := r.client(Config{MaxMeasurementsPerHour: 10, MaxCreditsPerDay: 1000}, testKey)
	other := manual()
	other.Prefix = netip.MustParsePrefix("203.0.113.0/24")
	other.Target = netip.MustParseAddr("203.0.113.9")
	for _, req := range []Request{manual(), other, manual()} {
		if _, err := c.Measure(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	got := c.Records(pfx)
	if len(got) != 2 || got[0].ID != 1003 || got[1].ID != 1001 {
		t.Errorf("records = %+v", got)
	}
	var nilClient *Client
	if nilClient.Records(pfx) != nil || nilClient.Status().State != StateOff {
		t.Error("a nil client is not off")
	}
}

func TestCorruptStateFileStartsEmpty(t *testing.T) {
	r := newRig(t)
	if err := os.WriteFile(r.state, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := r.client(Config{}, testKey)
	if st := c.Status(); st.CreditsToday != 0 {
		t.Errorf("status = %+v", st)
	}
	if !strings.Contains(r.logs.String(), "state file is not valid") {
		t.Errorf("not logged: %s", r.logs.String())
	}
}

func TestStateFileIsPrivate(t *testing.T) {
	r := newRig(t)
	c := r.client(Config{}, testKey)
	if _, err := c.Measure(context.Background(), manual()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(r.state)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("state file: %v %v", fi, err)
	}
}

func validate(c Config) []string {
	var errs []string
	c.Validate(func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) })
	return errs
}

func TestValidate(t *testing.T) {
	if errs := validate(Config{}); len(errs) != 0 {
		t.Errorf("empty block: %v", errs)
	}
	if errs := validate(Config{Enabled: true, ProbeID: 6001, Source: Source{Type: "asn", Value: "64496"}, Probes: 10, AfterMove: true}); len(errs) != 0 {
		t.Errorf("good block: %v", errs)
	}
	bad := []struct {
		cfg  Config
		want string
	}{
		{Config{Probes: 3}, "set enabled: true"},
		{Config{Enabled: true, Probes: 11}, "atlas.probes"},
		{Config{Enabled: true, ProbeID: -1}, "atlas.probe_id"},
		{Config{Enabled: true, AfterMoveDelay: time.Second}, "atlas.after_move_delay"},
		{Config{Enabled: true, MaxCreditsPerDay: 1000000}, "atlas.max_credits_per_day"},
		{Config{Enabled: true, MaxMeasurementsPerHour: 61}, "atlas.max_measurements_per_hour"},
		{Config{Enabled: true, Source: Source{Type: "area", Value: "Mars"}}, "atlas.source.value"},
		{Config{Enabled: true, Source: Source{Type: "country", Value: "de"}}, "atlas.source.value"},
		{Config{Enabled: true, Source: Source{Type: "asn", Value: "0"}}, "atlas.source.value"},
		{Config{Enabled: true, Source: Source{Type: "prefix", Value: "x"}}, "atlas.source.type"},
		{Config{Enabled: true, Source: Source{Value: "WW"}}, "atlas.source.type"},
	}
	for _, b := range bad {
		errs := validate(b.cfg)
		if len(errs) != 1 || !strings.Contains(errs[0], b.want) {
			t.Errorf("%+v: %v, want one error with %q", b.cfg, errs, b.want)
		}
	}
}

func TestPublicTarget(t *testing.T) {
	for addr, want := range map[string]bool{
		"198.51.100.7":        true,
		"2001:db8::7":         true,
		"::ffff:198.51.100.7": true,
		"10.0.0.1":            false,
		"127.0.0.1":           false,
		"169.254.1.1":         false,
		"100.64.0.1":          false,
		"0.1.2.3":             false,
		"240.0.0.1":           false,
		"255.255.255.255":     false,
		"224.0.0.1":           false,
		"::ffff:10.0.0.1":     false,
		"fd00::1":             false,
	} {
		if got := PublicTarget(netip.MustParseAddr(addr)); got != want {
			t.Errorf("PublicTarget(%s) = %v, want %v", addr, got, want)
		}
	}
	if PublicTarget(netip.Addr{}) {
		t.Error("the zero address is not a target")
	}
}

func TestMeasureSendsAMappedAddressAsIPv4(t *testing.T) {
	r := newRig(t)
	c := r.client(Config{}, testKey)
	req := manual()
	req.Target = netip.MustParseAddr("::ffff:198.51.100.7")
	if _, err := c.Measure(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	def := r.api.creates[0]["definitions"].([]any)[0].(map[string]any)
	if def["target"] != "198.51.100.7" || def["af"] != float64(4) {
		t.Errorf("definition = %v", def)
	}
}

func TestTestAddr(t *testing.T) {
	a, b, c := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("198.51.100.3")
	rows := []LocalRow{{Provider: "x", Target: a}, {Provider: "y", Target: b, Answered: true}, {Provider: "z", Target: c, Answered: true}, {Provider: "w"}}
	for _, tc := range []struct {
		name   string
		rows   []LocalRow
		prefer string
		want   netip.Addr
		ok     bool
	}{
		{"preferred provider wins", rows, "z", c, true},
		{"first answering row", rows, "", b, true},
		{"unknown provider falls back", rows, "nope", b, true},
		{"none answered: first with a target", []LocalRow{{Provider: "w"}, {Provider: "x", Target: a}, {Provider: "y", Target: b}}, "", a, true},
		{"no rows", nil, "x", netip.Addr{}, false},
		{"no targets", []LocalRow{{Provider: "x"}}, "x", netip.Addr{}, false},
	} {
		got, ok := TestAddr(tc.rows, tc.prefer)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: got %v %v, want %v %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}
