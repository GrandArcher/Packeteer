package preflight

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// good is a setup in which every check passes once the filters are confirmed.
func good() Facts {
	return Facts{
		Neighbors:   []Neighbor{{Address: "192.0.2.254", Established: true}},
		RIBReady:    true,
		Learned:     900000,
		Timers:      []Timers{{Address: "192.0.2.254", Hold: 90 * time.Second}},
		Providers:   []Provider{{Name: "transit-a", SourceIP: "192.0.2.11", NextHop: "192.0.2.1", Egress: EgressOK}},
		Community:   "64512:666",
		Announcer:   true,
		Fingerprint: "fp1",
		Confirmed:   map[string]Confirmation{CheckFilters: {By: "admin", At: t0}},
	}
}

func result(t *testing.T, f Facts, id string) Result {
	t.Helper()
	for _, r := range Run(f, t0).Results {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no result for %s", id)
	return Result{}
}

func TestRunReadyWhenEveryCheckPasses(t *testing.T) {
	rep := Run(good(), t0)
	if !rep.Ready || len(rep.Blocking()) != 0 {
		t.Fatalf("report = %+v", rep)
	}
	if len(rep.Results) != 5 {
		t.Fatalf("%d results, want one per check", len(rep.Results))
	}
	for _, r := range rep.Results {
		if r.Status != Pass || r.Fix != "" {
			t.Errorf("%s: %s with fix %q", r.ID, r.Status, r.Fix)
		}
	}
}

func TestSessionFailuresNameTheFix(t *testing.T) {
	cases := []struct {
		name   string
		mut    func(*Facts)
		status Status
		detail string
		fix    string
	}{
		{"no neighbor", func(f *Facts) { f.Neighbors = nil }, Fail, "No BGP neighbor", "bgp.neighbors"},
		{"session down", func(f *Facts) { f.Neighbors[0].Established = false }, Fail, "192.0.2.254", "same AS number"},
		{"rib loading", func(f *Facts) { f.RIBReady = false }, Fail, "still loading", "run the checks again"},
		{"empty rib", func(f *Facts) { f.Learned = 0 }, Fail, "no routes learned", "export policy toward Packeteer"},
		{"tiny rib", func(f *Facts) { f.Learned = 3 }, Warn, "only 3 prefixes", "lab"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := good()
			c.mut(&f)
			r := result(t, f, CheckSession)
			if r.Status != c.status || !strings.Contains(r.Detail, c.detail) || !strings.Contains(strings.ToLower(r.Fix), strings.ToLower(c.fix)) {
				t.Fatalf("result = %+v", r)
			}
			if r.Blocking() != (c.status == Fail) {
				t.Fatalf("blocking = %v for %s", r.Blocking(), r.Status)
			}
		})
	}
}

func TestFiltersNeedConfirmationAndLeaksFail(t *testing.T) {
	f := good()
	f.Confirmed = nil
	r := result(t, f, CheckFilters)
	if r.Status != Unverified || !r.Confirmable || !r.Blocking() {
		t.Fatalf("unconfirmed = %+v", r)
	}
	for _, want := range []string{"64512:666", "rejects everything else", "every eBGP neighbor"} {
		if !strings.Contains(r.Fix, want) {
			t.Errorf("fix %q lacks %q", r.Fix, want)
		}
	}
	f.Leaks = 2
	r = result(t, f, CheckFilters)
	if r.Status != Fail || r.Confirmable || !strings.Contains(r.Detail, "2 prefix") || !strings.Contains(r.Fix, "outbound policy of every eBGP neighbor") {
		t.Fatalf("leak = %+v", r)
	}
	f.Confirmed = good().Confirmed
	if r := result(t, f, CheckFilters); r.Status != Fail {
		t.Fatalf("a confirmation must not hide a leak: %+v", r)
	}
}

func TestEgressChecksEachProvider(t *testing.T) {
	f := good()
	f.Providers = []Provider{
		{Name: "transit-a", SourceIP: "192.0.2.11", NextHop: "192.0.2.1", Egress: EgressOK},
		{Name: "transit-b", SourceIP: "192.0.2.12", NextHop: "192.0.2.2", Egress: EgressMismatch, FirstHop: "192.0.2.1"},
		{Name: "transit-c", SourceIP: "192.0.2.13", NextHop: "192.0.2.3", Egress: EgressNoReply, Why: "no answer"},
	}
	r := result(t, f, CheckEgress)
	if r.Status != Fail {
		t.Fatalf("status = %s", r.Status)
	}
	for _, want := range []string{"transit-b: probes from 192.0.2.12 left through 192.0.2.1, expected 192.0.2.2", "transit-c: probes from 192.0.2.13 got no answer"} {
		if !strings.Contains(r.Detail, want) {
			t.Errorf("detail lacks %q:\n%s", want, r.Detail)
		}
	}
	if !strings.Contains(r.Fix, "packeteer -pbr linux -apply") {
		t.Errorf("fix = %q", r.Fix)
	}

	f.Providers = []Provider{{Name: "transit-a", SourceIP: "192.0.2.11", NextHop: "192.0.2.1", Egress: EgressUnchecked, Why: "path_check is off"}}
	r = result(t, f, CheckEgress)
	if r.Status != Warn || r.Blocking() || !strings.Contains(r.Detail, "path_check is off") || !strings.Contains(r.Fix, "traceroute -s") {
		t.Fatalf("unchecked = %+v", r)
	}

	f.Providers = nil
	if r := result(t, f, CheckEgress); r.Status != Fail || !strings.Contains(r.Fix, "next_hop") {
		t.Fatalf("no providers = %+v", r)
	}
}

func TestTimersAndGracefulRestart(t *testing.T) {
	cases := []struct {
		name   string
		t      Timers
		status Status
		fix    string
	}{
		{"timer off", Timers{Address: "192.0.2.254"}, Fail, "hold time 90"},
		{"local graceful restart", Timers{Address: "192.0.2.254", Hold: 90 * time.Second, LocalGR: true}, Fail, "never enables graceful restart"},
		{"long hold", Timers{Address: "192.0.2.254", Hold: 240 * time.Second}, Warn, "3m0s or less"},
		{"router graceful restart", Timers{Address: "192.0.2.254", Hold: 90 * time.Second, RouterGR: true}, Pass, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := good()
			f.Timers = []Timers{c.t}
			r := result(t, f, CheckTimers)
			if r.Status != c.status || !strings.Contains(r.Fix, c.fix) {
				t.Fatalf("result = %+v", r)
			}
		})
	}
	f := good()
	f.Timers = nil
	if r := result(t, f, CheckTimers); r.Status != Fail {
		t.Fatalf("no session = %+v", r)
	}
	f.TimersErr = "speaker stopped"
	if r := result(t, f, CheckTimers); r.Status != Fail || !strings.Contains(r.Detail, "speaker stopped") {
		t.Fatalf("read error = %+v", r)
	}
}

func TestWithdrawalNeedsAnnouncerAndBoundedHold(t *testing.T) {
	f := good()
	f.Announcer = false
	if r := result(t, f, CheckWithdrawal); r.Status != Fail || !strings.Contains(r.Fix, "announcer: {type: gobgp}") {
		t.Fatalf("no announcer = %+v", r)
	}
	f = good()
	f.Timers[0].Hold = 0
	if r := result(t, f, CheckWithdrawal); r.Status != Fail || !strings.Contains(r.Fix, "timers check") {
		t.Fatalf("no hold timer = %+v", r)
	}
	f = good()
	f.Timers = nil
	if r := result(t, f, CheckWithdrawal); r.Status != Fail {
		t.Fatalf("no session = %+v", r)
	}
	r := result(t, good(), CheckWithdrawal)
	if r.Status != Pass || !strings.Contains(r.Detail, "within 1m30s") || !strings.Contains(r.Detail, "Not checked: a live test route") {
		t.Fatalf("pass = %+v", r)
	}
}

func TestReportBlockingListsEveryBlockingCheck(t *testing.T) {
	f := good()
	f.Confirmed = nil
	f.Providers[0].Egress = EgressMismatch
	f.Learned = 3
	rep := Run(f, t0)
	if rep.Ready {
		t.Fatal("ready with failing checks")
	}
	got := strings.Join(rep.Blocking(), ",")
	if got != CheckFilters+","+CheckEgress {
		t.Fatalf("blocking = %s (a warning must not block)", got)
	}
}

func source(f *Facts) Source { return func(context.Context) Facts { return *f } }

func TestRunnerKeepsLatestAndAppliesConfirmations(t *testing.T) {
	f := good()
	f.Confirmed = nil
	store, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	r := NewRunner(source(&f), store, func() time.Time { return t0 })
	if _, ok := r.Latest(); ok {
		t.Fatal("latest before any run")
	}
	if rep := r.Run(context.Background()); rep.Ready {
		t.Fatal("ready before the filters are confirmed")
	}
	if rep, ok := r.Latest(); !ok || rep.Ready || !rep.RanAt.Equal(t0) {
		t.Fatalf("latest = %+v, %v", rep, ok)
	}
	rep, err := r.Confirm(context.Background(), CheckFilters, "admin")
	if err != nil || !rep.Ready {
		t.Fatalf("confirm = %+v, %v", rep, err)
	}
	for _, res := range rep.Results {
		if res.ID == CheckFilters && !strings.Contains(res.Detail, "Confirmed by admin at 2026-01-02T03:04:05Z") {
			t.Fatalf("detail = %q", res.Detail)
		}
	}
	// A different community or neighbor voids the confirmation.
	f.Fingerprint = "fp2"
	if rep := r.Run(context.Background()); rep.Ready {
		t.Fatal("confirmation survived a changed setup")
	}
}

func TestConfirmRefusals(t *testing.T) {
	f := good()
	f.Confirmed = nil
	store, _ := OpenStore("")
	r := NewRunner(source(&f), store, func() time.Time { return t0 })
	for _, id := range []string{CheckSession, CheckEgress, CheckTimers, CheckWithdrawal, "nope"} {
		if _, err := r.Confirm(context.Background(), id, "admin"); !errors.Is(err, ErrNotConfirmable) {
			t.Errorf("confirm %s = %v, want ErrNotConfirmable", id, err)
		}
	}
	f.Leaks = 1
	if _, err := r.Confirm(context.Background(), CheckFilters, "admin"); !errors.Is(err, ErrFailing) {
		t.Fatalf("confirm over a leak = %v, want ErrFailing", err)
	}
	if got := store.Active("fp1"); len(got) != 0 {
		t.Fatalf("a refused confirmation was stored: %v", got)
	}
	if _, err := NewRunner(source(&f), nil, nil).Confirm(context.Background(), CheckFilters, "admin"); err == nil {
		t.Fatal("confirmed without a store")
	}
}

func TestGateRefusesUntilReady(t *testing.T) {
	f := good()
	f.Learned = 0
	r := NewRunner(source(&f), mustStore(t, ""), func() time.Time { return t0 })
	err := r.Gate(context.Background(), f.Fingerprint)
	var nr *NotReadyError
	if !errors.As(err, &nr) || !strings.Contains(err.Error(), CheckSession) || nr.Report.Ready {
		t.Fatalf("gate = %v", err)
	}
	f.Learned = 900000
	f.Confirmed = nil
	// The store, not the facts, supplies confirmations: confirm first.
	if err := r.Gate(context.Background(), f.Fingerprint); err == nil || !strings.Contains(err.Error(), CheckFilters) {
		t.Fatalf("gate before confirm = %v", err)
	}
	if _, err := r.Confirm(context.Background(), CheckFilters, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := r.Gate(context.Background(), f.Fingerprint); err != nil {
		t.Fatalf("gate after confirm = %v", err)
	}
}

func TestGateRefusesACandidateThatChangesTheSetup(t *testing.T) {
	f := good()
	f.Fingerprint = "running"
	r := NewRunner(source(&f), mustStore(t, ""), func() time.Time { return t0 })
	if _, err := r.Confirm(context.Background(), CheckFilters, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := r.Gate(context.Background(), "running"); err != nil {
		t.Fatalf("same setup: %v", err)
	}
	if err := r.Gate(context.Background(), "other"); !errors.Is(err, ErrSetupChanged) {
		t.Fatalf("changed setup: %v", err)
	}
}

func mustStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStorePersistsPerFingerprint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "preflight.json")
	s := mustStore(t, path)
	if err := s.Set("fp1", CheckFilters, Confirmation{By: "admin", At: t0}); err != nil {
		t.Fatal(err)
	}
	again := mustStore(t, path)
	got := again.Active("fp1")
	if c := got[CheckFilters]; c.By != "admin" || !c.At.Equal(t0) {
		t.Fatalf("reloaded = %v", got)
	}
	if got := again.Active("fp2"); len(got) != 0 {
		t.Fatalf("another setup sees %v", got)
	}
	if err := again.Set("fp2", CheckFilters, Confirmation{By: "ops", At: t0}); err != nil {
		t.Fatal(err)
	}
	if got := mustStore(t, path).Active("fp1"); len(got) != 0 {
		t.Fatalf("a new fingerprint kept the old confirmation: %v", got)
	}
}

func TestStoreErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(bad); err == nil {
		t.Fatal("opened a corrupt file")
	}
	s := mustStore(t, filepath.Join(dir, "missing", "preflight.json"))
	if err := s.Set("fp", CheckFilters, Confirmation{By: "a", At: t0}); err == nil {
		t.Fatal("wrote into a missing directory")
	}
	if got := s.Active("fp"); len(got) != 0 {
		t.Fatalf("a failed write was remembered: %v", got)
	}
}
