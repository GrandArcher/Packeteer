package httpapi

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/eventlog"
	"github.com/GrandArcher/Packeteer/internal/pin"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// storePins is a PinControl over a real store with fixed rails.
type storePins struct {
	s     *pin.Store
	rails pin.Rails
}

func newStorePins() storePins {
	return storePins{s: pin.NewStore(), rails: pin.Rails{
		Providers: []string{"transit-a", "transit-b"},
		Allowlist: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Learned:   func(p netip.Prefix) bool { return p == netip.MustParsePrefix("198.51.100.0/24") },
	}}
}

func (p storePins) List(now time.Time) []pin.Pin { return p.s.List(now) }
func (p storePins) Add(r pin.Request, now time.Time) (pin.Pin, error) {
	return p.s.Add(r, p.rails, now)
}
func (p storePins) Remove(id string) bool { _, ok := p.s.Remove(id); return ok }

type fakeOpt struct{ st Pause }

func (f *fakeOpt) State() Pause { return f.st }
func (f *fakeOpt) Pause(by, reason string, now time.Time) (Pause, bool) {
	if f.st.Paused {
		return f.st, false
	}
	f.st = Pause{Paused: true, By: by, Reason: reason, Since: now}
	return f.st, true
}
func (f *fakeOpt) Resume() bool {
	was := f.st.Paused
	f.st = Pause{}
	return was
}

func steerServer(t *testing.T, user string, pins PinControl, opt OptimizationControl, events *eventlog.Log) http.Handler {
	t.Helper()
	pass := ""
	if user != "" {
		pass = "secret"
	}
	s, err := New(Options{User: user, Password: pass, Events: events, Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	if pins != nil {
		s.SetSteering(pins, opt)
	}
	return s.Handler()
}

const pinBody = `{"prefix":"198.51.100.0/24","provider":"transit-b","max_loss_pct":2,"max_rtt_ms":80,"duration":"1h","reason":"lab"}`

func TestPinEndpoints(t *testing.T) {
	pins := newStorePins()
	h := steerServer(t, "ops", pins, &fakeOpt{}, nil)
	const js = "application/json"

	rec := mdo(h, http.MethodPost, "/api/pins", js, pinBody, true)
	var got pin.Pin
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	if got.ID != "pin-1" || got.By != "ops" || got.Provider != "transit-b" || got.MaxRTTMs != 80 || got.Expires.Sub(got.Created) != time.Hour {
		t.Fatalf("pin %+v", got)
	}
	rec = mdo(h, http.MethodGet, "/api/pins", "", "", true)
	var list struct {
		Writable bool
		Pins     []pin.Pin
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil || !list.Writable || len(list.Pins) != 1 || list.Pins[0].ID != "pin-1" {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}

	for name, tc := range map[string]struct {
		ctype, body string
		code        int
		want        string
	}{
		"second pin":      {js, pinBody, http.StatusConflict, "already pinned"},
		"not allowlisted": {js, strings.Replace(pinBody, "198.51.100.0/24", "203.0.113.0/24", 1), http.StatusBadRequest, "allowlist"},
		"no loss ceiling": {js, `{"prefix":"198.51.100.0/24","provider":"transit-b","duration":"1h"}`, http.StatusBadRequest, "max_loss_pct is required"},
		"bad duration":    {js, strings.Replace(pinBody, `"1h"`, `"soon"`, 1), http.StatusBadRequest, "duration"},
		"bad prefix":      {js, strings.Replace(pinBody, "198.51.100.0/24", "nope", 1), http.StatusBadRequest, "prefix"},
		"unknown field":   {js, `{"prefix":"198.51.100.0/24","community":"64496:1"}`, http.StatusBadRequest, "unknown field"},
		"form post":       {"application/x-www-form-urlencoded", "prefix=198.51.100.0/24", http.StatusUnsupportedMediaType, "application/json"},
	} {
		rec := mdo(h, http.MethodPost, "/api/pins", tc.ctype, tc.body, true)
		if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if n := len(pins.List(time.Now())); n != 1 {
		t.Fatalf("refused requests changed the pins: %d", n)
	}

	if rec := mdo(h, http.MethodDelete, "/api/pins/pin-1", "", "", true); rec.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body)
	}
	if rec := mdo(h, http.MethodDelete, "/api/pins/pin-1", "", "", true); rec.Code != http.StatusNotFound {
		t.Fatalf("remove again: %d", rec.Code)
	}

	// With no sign-in at all nobody can change pins.
	open := steerServer(t, "", newStorePins(), &fakeOpt{}, nil)
	if rec := mdo(open, http.MethodPost, "/api/pins", js, pinBody, false); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "requires auth") {
		t.Fatalf("anonymous add: %d %s", rec.Code, rec.Body)
	}
}

func TestOptimizationPauseAndResume(t *testing.T) {
	opt := &fakeOpt{}
	h := steerServer(t, "ops", newStorePins(), opt, nil)
	const js = "application/json"
	if rec := mdo(h, http.MethodPost, "/api/optimization/pause", js, `{}`, true); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "reason is required") {
		t.Fatalf("no reason: %d %s", rec.Code, rec.Body)
	}
	if opt.st.Paused {
		t.Fatal("paused without a reason")
	}
	rec := mdo(h, http.MethodPost, "/api/optimization/pause", js, `{"reason":"upstream incident"}`, true)
	if rec.Code != http.StatusOK || !opt.st.Paused || opt.st.By != "ops" || opt.st.Reason != "upstream incident" {
		t.Fatalf("pause: %d %s %+v", rec.Code, rec.Body, opt.st)
	}
	if rec := mdo(h, http.MethodPost, "/api/optimization/pause", js, `{"reason":"again"}`, true); rec.Code != http.StatusConflict || opt.st.Reason != "upstream incident" {
		t.Fatalf("pause twice: %d %+v", rec.Code, opt.st)
	}
	rec = mdo(h, http.MethodGet, "/api/optimization", "", "", true)
	var st struct {
		Writable bool
		Pause
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &st) != nil || !st.Paused || st.By != "ops" || !st.Writable {
		t.Fatalf("state: %d %s", rec.Code, rec.Body)
	}
	if rec := mdo(h, http.MethodDelete, "/api/optimization/pause", "", "", true); rec.Code != http.StatusNoContent || opt.st.Paused {
		t.Fatalf("resume: %d %+v", rec.Code, opt.st)
	}
	if rec := mdo(h, http.MethodDelete, "/api/optimization/pause", "", "", true); rec.Code != http.StatusConflict {
		t.Fatalf("resume twice: %d", rec.Code)
	}
}

func TestAlertAcknowledge(t *testing.T) {
	log := eventlog.New(nil, nil, nil)
	down := plugin.Event{Time: time.Now().Add(-time.Minute), Kind: plugin.EventProviderDown, Severity: plugin.SeverityCritical, Message: "down", Fields: map[string]string{"provider": "transit-a"}}
	log.Record(down)
	h := steerServer(t, "ops", nil, nil, log)
	const js = "application/json"

	type row struct {
		Kind     string
		DedupKey string `json:"dedup_key"`
		Ack      *eventlog.Ack
	}
	rows := func() []row {
		t.Helper()
		rec := mdo(h, http.MethodGet, "/api/events", "", "", true)
		var body struct{ Events []row }
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
			t.Fatalf("events: %d %s", rec.Code, rec.Body)
		}
		return body.Events
	}
	if r := rows(); len(r) != 1 || r[0].DedupKey != down.DedupKey() || r[0].Ack != nil {
		t.Fatalf("rows before ack %+v", r)
	}

	if rec := mdo(h, http.MethodPost, "/api/alerts/ack", js, `{"key":"packeteer/provider/provider=transit-z"}`, true); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown key: %d %s", rec.Code, rec.Body)
	}
	if rec := mdo(h, http.MethodPost, "/api/alerts/ack", js, `{"note":"x"}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("no key: %d %s", rec.Code, rec.Body)
	}
	rec := mdo(h, http.MethodPost, "/api/alerts/ack", js, `{"key":"`+down.DedupKey()+`","note":"ticket 7"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("ack: %d %s", rec.Code, rec.Body)
	}
	if r := rows(); r[0].Ack == nil || r[0].Ack.By != "ops" || r[0].Ack.Note != "ticket 7" {
		t.Fatalf("rows after ack %+v", r)
	}

	log.Record(plugin.Event{Time: time.Now(), Kind: plugin.EventProviderUp, Severity: plugin.SeverityInfo, Fields: map[string]string{"provider": "transit-a"}})
	if r := rows(); len(r) != 2 || r[1].Ack != nil {
		t.Fatalf("ack kept after resolve %+v", r)
	}
	if rec := mdo(h, http.MethodPost, "/api/alerts/ack", js, `{"key":"`+down.DedupKey()+`"}`, true); rec.Code != http.StatusConflict {
		t.Fatalf("resolved: %d %s", rec.Code, rec.Body)
	}
}
