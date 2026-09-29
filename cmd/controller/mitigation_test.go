package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
)

// packeteerPath is Packeteer's path for prefix on the simulated edge: its
// next hop and communities. ok is false when there is none.
func packeteerPath(t *testing.T, srv *server.BgpServer, prefix string) (nh string, comms map[uint32]bool, ok bool) {
	t.Helper()
	err := srv.ListPath(context.Background(), &api.ListPathRequest{TableType: api.TableType_ADJ_IN, Name: "127.0.0.2", Family: v4}, func(d *api.Destination) {
		if d.Prefix != prefix {
			return
		}
		for _, p := range d.Paths {
			if p.IsWithdraw {
				continue
			}
			ok, comms = true, map[uint32]bool{}
			for _, a := range p.Pattrs {
				var ca api.CommunitiesAttribute
				var na api.NextHopAttribute
				switch {
				case a.MessageIs(&ca) && a.UnmarshalTo(&ca) == nil:
					for _, c := range ca.Communities {
						comms[c] = true
					}
				case a.MessageIs(&na) && a.UnmarshalTo(&na) == nil:
					nh = na.NextHop
				}
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return nh, comms, ok
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestDaemonMitigationBlackholeRedirectExpireWithdraw runs the controller
// in inject against a simulated edge that advertises 203.0.113.0/24. Rules
// come in through the ops API. A blackhole reaches the edge with the
// discard next hop, the packeteer community, the marker, BLACKHOLE, and
// NO_EXPORT, and its TTL withdraws it. A prefix that is allowlisted but
// not learned is never announced. A redirect goes to the scrubber's next
// hop, and shutdown withdraws it while the session is still up.
func TestDaemonMitigationBlackholeRedirectExpireWithdraw(t *testing.T) {
	srv, port := edgeRouter(t)
	httpPort := freePort(t)
	dir := t.TempDir()
	cfg := fmt.Sprintf(`mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 1s
thresholds: {min_loss_delta_pct: 90, min_rtt_delta_ms: 5000}
http: {listen: "127.0.0.1:%d"}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
allowlist: {prefixes: ["198.51.100.0/24"]}
probe: {interval: 1s, timeout: 200ms, packets: 1}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 1}, {provider: transit-b, rtt_ms: 1}]}
bgp:
  neighbors:
    - {address: 127.0.0.1, port: %d, local_address: 127.0.0.2}
announcer: {type: gobgp}
mitigation:
  mode: inject
  allowlist: [203.0.113.0/24]
  max_rules: 2
  announcer:
    type: gobgp
    config:
      marker: "64512:668"
      blackhole: {next_hop: 192.0.2.66}
      redirect:
        - {name: scrubber, next_hop: 192.0.2.77, communities: ["64512:777"]}
`, httpPort, port)
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(k string) string {
		switch k {
		case HTTPUserEnv:
			return "lab"
		case HTTPPassEnv:
			return "lab-only"
		}
		return ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, logs syncBuf
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"-config", path}, env, &out, &logs) }()

	base := fmt.Sprintf("http://127.0.0.1:%d/api/mitigations", httpPort)
	call := func(method, url, body string) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequest(method, url, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("lab", "lab-only")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, nil
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		return resp.StatusCode, m
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s\n%s", what, logs.String())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	waitFor("the ops API", func() bool { code, _ := call(http.MethodGet, base, ""); return code == http.StatusOK })

	has := func(comms map[uint32]bool, want ...uint32) bool {
		if len(comms) != len(want) {
			return false
		}
		for _, c := range want {
			if !comms[c] {
				return false
			}
		}
		return true
	}
	const (
		pc     = 64512<<16 | 666
		marker = 64512<<16 | 668
		bh     = 0xFFFF029A // 65535:666
		noExp  = 0xFFFFFF01
	)

	// Outside the mitigation allowlist: refused.
	if code, _ := call(http.MethodPost, base, `{"prefix":"198.51.100.0/24","action":"blackhole"}`); code != http.StatusBadRequest {
		t.Fatalf("rule outside the mitigation allowlist: %d", code)
	}
	// Allowlisted but not learned: held, never announced.
	if code, _ := call(http.MethodPost, base, `{"prefix":"203.0.113.128/25","action":"blackhole","ttl":"1m"}`); code != http.StatusCreated {
		t.Fatalf("pending rule: %d", code)
	}
	// RTBH with a short TTL.
	code, rule := call(http.MethodPost, base, `{"prefix":"203.0.113.0/24","action":"blackhole","ttl":"3s","reason":"test"}`)
	if code != http.StatusCreated || rule["id"] == "" {
		t.Fatalf("blackhole rule: %d %v", code, rule)
	}
	// max_rules 2: a third prefix is refused.
	if code, _ := call(http.MethodPost, base, `{"prefix":"203.0.113.0/25","action":"blackhole"}`); code != http.StatusConflict {
		t.Fatalf("rule past max_rules: %d", code)
	}
	waitFor("blackhole on the edge", func() bool {
		nh, comms, ok := packeteerPath(t, srv, "203.0.113.0/24")
		return ok && nh == "192.0.2.66" && has(comms, pc, marker, bh, noExp)
	})
	if _, _, ok := packeteerPath(t, srv, "203.0.113.128/25"); ok {
		t.Fatal("a prefix not in the learned RIB was announced")
	}
	waitFor("TTL expiry withdraws the blackhole", func() bool {
		_, _, ok := packeteerPath(t, srv, "203.0.113.0/24")
		return !ok
	})
	if !strings.Contains(logs.String(), "mitigation rule expired") {
		t.Fatalf("no expiry log:\n%s", logs.String())
	}

	// Redirect to the scrubber, then shutdown withdraws it.
	if code, _ := call(http.MethodPost, base, `{"prefix":"203.0.113.0/24","action":"redirect","target":"scrubber","ttl":"10m"}`); code != http.StatusCreated {
		t.Fatalf("redirect rule: %d", code)
	}
	waitFor("redirect on the edge", func() bool {
		nh, comms, ok := packeteerPath(t, srv, "203.0.113.0/24")
		return ok && nh == "192.0.2.77" && has(comms, pc, marker, 64512<<16|777, noExp)
	})
	_, st := call(http.MethodGet, base, "")
	if st["enabled"] != true || st["mitigation_mode"] != "inject" || len(st["rules"].([]any)) != 2 {
		t.Fatalf("status = %v", st)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, logs.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("daemon did not stop")
	}
	text := logs.String()
	if !strings.Contains(text, "mitigation routes withdrawn") {
		t.Fatalf("shutdown did not withdraw mitigation routes:\n%s", text)
	}
	if strings.Contains(text, "msg=injected") {
		t.Fatalf("an outbound improvement was announced:\n%s", text)
	}
	waitFor("redirect gone after shutdown", func() bool {
		_, _, ok := packeteerPath(t, srv, "203.0.113.0/24")
		return !ok
	})
}

func TestMitigationCheckAndCatalogConflicts(t *testing.T) {
	base := `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
allowlist: {prefixes: ["198.51.100.0/24"]}
mitigation:
  allowlist: [203.0.113.0/24]
  announcer:
    type: gobgp
    config:
      marker: "64512:668"
      blackhole: {next_hop: %s}
`
	parse := func(nh string) (*config.Config, *pluginhost.Set) {
		t.Helper()
		cfg, err := config.Parse([]byte(fmt.Sprintf(base, nh)))
		if err != nil {
			t.Fatal(err)
		}
		set, err := pluginhost.Build(cfg, pluginhost.Options{})
		if err != nil {
			t.Fatal(err)
		}
		return cfg, set
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg, set := parse("192.0.2.1")
	if _, err := newMitigation(cfg, set, log); err == nil || !strings.Contains(err.Error(), "transit-a") {
		t.Fatalf("catalog reusing a provider next hop: %v", err)
	}
	cfg, set = parse("192.0.2.66")
	mit, err := newMitigation(cfg, set, log)
	if err != nil || mit == nil {
		t.Fatalf("observe mitigation: %v", err)
	}
	// Observe binds nothing and needs no RIB.
	if err := bindMitigation(cfg, set, nil); err != nil {
		t.Fatal(err)
	}
	if err := setMitigationRIB(mit, nil); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(base, "192.0.2.66")), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"-config", path, "-check"}, noEnv, &out, &errb); code != 0 {
		t.Fatalf("check exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "mitigation: observe allowlist=1 max_rules=10 default_ttl=1h0m0s max_ttl=24h0m0s") ||
		!strings.Contains(out.String(), "announcer mitigation gobgp") {
		t.Fatalf("check output:\n%s", out.String())
	}
}
