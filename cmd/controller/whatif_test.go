package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/plugins/storage/sqlite"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/replay"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const whatIfConfig = `mode: observe
asn: 64512
router_id: 192.0.2.10
hold_time: 2m
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: %d}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
storage:
  type: sqlite
  config: {path: %s, round_retention: 720h}
`

// whatIfEnv is a config on disk with a sqlite history that holds a recorded
// run: 198.51.100.0/24 loses 20% on transit-a, 203.0.113.0/24 is 20 ms
// slower on transit-a. The store stays open, as under a running controller.
type whatIfEnv struct {
	dir, base, candidate string
	store                *sqlite.Store
}

func newWhatIfEnv(t *testing.T, rounds int) *whatIfEnv {
	t.Helper()
	ctx := context.Background()
	e := &whatIfEnv{dir: t.TempDir()}
	db := filepath.Join(e.dir, "data", "packeteer.db")
	e.base = filepath.Join(e.dir, "config.yaml")
	if err := os.WriteFile(e.base, []byte(fmt.Sprintf(whatIfConfig, 15, db)), 0o600); err != nil {
		t.Fatal(err)
	}
	e.candidate = filepath.Join(e.dir, "new.yaml")
	if err := os.WriteFile(e.candidate, []byte(fmt.Sprintf(whatIfConfig, 30, db)), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := plugin.ConfigFromYAML("path: " + db + "\nround_retention: 720h")
	st, err := sqlite.New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Stop(ctx) })
	e.store = st
	pA, pB := netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24")
	start := time.Now().UTC().Add(-time.Hour)
	var recs []plugin.RoundRecord
	for i := 0; i < rounds; i++ {
		at := start.Add(time.Duration(i) * 30 * time.Second)
		res := func(p netip.Prefix, prov string, loss, rtt float64) probe.Result {
			return probe.Result{Provider: prov, Prefix: p, Time: at, Round: at,
				Stats: probe.Stats{Sent: 10, Received: 10 - int(loss/10), LossPct: loss, RTTAvg: time.Duration(rtt * float64(time.Millisecond))}}
		}
		in := policy.Input{
			Results:    []probe.Result{res(pA, "transit-a", 20, 40), res(pA, "transit-b", 0, 45), res(pB, "transit-a", 0, 80), res(pB, "transit-b", 0, 60)},
			ProviderUp: map[string]bool{"transit-a": true, "transit-b": true}, RIBEnabled: true, RIBReady: true,
			Native: map[netip.Prefix]string{pA: "transit-a", pB: "transit-a"},
		}
		data, err := replay.Encode(at, in)
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, plugin.RoundRecord{At: at, Input: data})
	}
	if err := st.PutRounds(ctx, recs); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestWhatIfCommand(t *testing.T) {
	e := newWhatIfEnv(t, 12)
	var out, errOut bytes.Buffer
	args := []string{"whatif", "-base", e.base, "-config", e.candidate, "-from", "3h"}
	if code := run(context.Background(), args, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, want := range []string{"replayed 12 rounds", "nothing was announced", "running config", "candidate config", "203.0.113.0/24  base: transit-b  new: (no move)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "198.51.100.0/24  base") {
		t.Errorf("198.51.100.0/24 is steered the same by both configs but is listed:\n%s", out.String())
	}

	out.Reset()
	if code := run(context.Background(), append(args, "-json"), noEnv, &out, &errOut); code != 0 {
		t.Fatalf("json exit %d: %s", code, errOut.String())
	}
	var res replay.Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Rounds != 12 || len(res.Sides) != 2 || res.Sides[0].Summary.Prefixes != 2 || res.Sides[1].Summary.Prefixes != 1 || len(res.Diff) != 1 {
		t.Fatalf("json result = %+v", res)
	}

	// Without -config only the running config is replayed, from observe
	// mode history.
	out.Reset()
	if code := run(context.Background(), []string{"whatif", "-base", e.base}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("single exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "running config") || strings.Contains(out.String(), "candidate config") || strings.Contains(out.String(), "steered differently") {
		t.Fatalf("single-config output:\n%s", out.String())
	}
}

func TestWhatIfCommandRefusals(t *testing.T) {
	e := newWhatIfEnv(t, 3)
	noStorage := filepath.Join(e.dir, "nostorage.yaml")
	if err := os.WriteFile(noStorage, []byte(strings.Split(fmt.Sprintf(whatIfConfig, 15, "x"), "storage:")[0]), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"empty window", []string{"-base", e.base, "-from", "300h", "-to", "200h"}, "no decision rounds"},
		{"bad window", []string{"-base", e.base, "-from", "soon"}, "neither an RFC 3339 time"},
		{"no storage", []string{"-base", noStorage}, "no storage"},
		{"missing candidate", []string{"-base", e.base, "-config", filepath.Join(e.dir, "none.yaml")}, "none.yaml"},
		{"missing base", []string{"-base", filepath.Join(e.dir, "none.yaml")}, "none.yaml"},
	} {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), append([]string{"whatif"}, c.args...), noEnv, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), c.want) {
			t.Errorf("%s: exit %d, stderr %q, want %q", c.name, code, errOut.String(), c.want)
		}
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"whatif", "-nope"}, noEnv, &out, &errOut); code != 2 {
		t.Errorf("unknown flag: exit %d", code)
	}
}

func TestWhatIfSource(t *testing.T) {
	e := newWhatIfEnv(t, 12)
	running, err := config.Load(e.base)
	if err != nil {
		t.Fatal(err)
	}
	cand, err := os.ReadFile(e.candidate)
	if err != nil {
		t.Fatal(err)
	}
	src := &whatIfSource{live: &liveConfig{cfg: running}, store: e.store, check: config.Parse, log: newLogger(&bytes.Buffer{}, "info", "text"), getenv: noEnv}
	res, err := src.Replay(context.Background(), cand, "3h", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sides) != 2 || len(res.Diff) != 1 || res.Diff[0].Prefix != netip.MustParsePrefix("203.0.113.0/24") {
		t.Fatalf("result = %+v", res)
	}
	if res, err = src.Replay(context.Background(), nil, "3h", ""); err != nil || len(res.Sides) != 1 {
		t.Fatalf("running config only: %+v %v", res, err)
	}
	if _, err = src.Replay(context.Background(), []byte("providers: ["), "3h", ""); !errors.Is(err, httpapi.ErrWhatIfInput) {
		t.Fatalf("bad candidate: %v", err)
	}
	if _, err = src.Replay(context.Background(), cand, "3h", "5h"); !errors.Is(err, httpapi.ErrWhatIfInput) {
		t.Fatalf("bad window: %v", err)
	}
	if _, err = src.Replay(context.Background(), cand, "300h", "200h"); !errors.Is(err, replay.ErrNoRounds) {
		t.Fatalf("empty window: %v", err)
	}
	src.busy.Store(true)
	if _, err = src.Replay(context.Background(), cand, "3h", ""); !errors.Is(err, httpapi.ErrWhatIfBusy) {
		t.Fatalf("busy: %v", err)
	}
	if !src.busy.Load() {
		t.Fatal("a refused replay cleared the running one's flag")
	}
}

// A daemon run with round_retention stores the input of each decision
// round, and `whatif` replays them. Without BGP neighbors there is no native
// path, so Decide makes no move; the test checks what the daemon wrote.
func TestDaemonStoresRoundsForReplay(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "data", "packeteer.db")
	body := `mode: observe
asn: 64512
router_id: 192.0.2.10
http: {listen: ""}
hold_time: 1m
thresholds: {min_loss_delta_pct: 5, min_rtt_delta_ms: 10}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
probe: {interval: 1s, timeout: 100ms, packets: 2}
probers:
  - type: fixed
    config:
      paths:
        - {provider: transit-a, rtt_ms: 40, loss_pct: 50}
        - {provider: transit-b, rtt_ms: 20}
sources:
  - type: static
    config: {targets: [{prefix: 198.51.100.0/24}]}
storage:
  type: sqlite
  config: {path: ` + db + `, round_retention: 24h}
`
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	var out, errOut bytes.Buffer
	if code := run(ctx, []string{"-config", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d\n%s", code, errOut.String())
	}

	c, _ := plugin.ConfigFromYAML("path: " + db)
	st, err := sqlite.New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer st.Stop(context.Background())
	now := time.Now().UTC()
	rounds, err := st.Rounds(context.Background(), now.Add(-time.Hour), now.Add(time.Hour), 100)
	if err != nil || len(rounds) == 0 {
		t.Fatalf("the daemon stored no rounds: %v", err)
	}
	last := rounds[len(rounds)-1]
	at, in, err := replay.Decode(last.Input)
	if err != nil || at.Sub(last.At).Abs() >= time.Millisecond {
		t.Fatalf("stored round: %v %v", at, err)
	}
	seen := map[string]float64{}
	for _, r := range in.Results {
		seen[r.Provider] = r.Stats.LossPct
	}
	if len(seen) != 2 || seen["transit-a"] != 50 || seen["transit-b"] != 0 || !in.ProviderUp["transit-a"] {
		t.Fatalf("stored round inputs = %+v up=%v", seen, in.ProviderUp)
	}

	out.Reset()
	errOut.Reset()
	if code := run(context.Background(), []string{"whatif", "-base", path, "-from", "1h", "-json"}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("whatif exit %d: %s", code, errOut.String())
	}
	var res replay.Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || res.Rounds != len(rounds) {
		t.Fatalf("replayed %d rounds, stored %d: %v", res.Rounds, len(rounds), err)
	}
}
