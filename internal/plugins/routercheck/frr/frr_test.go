package frr

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/readonly"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// The replies below follow what FRR 10 bgpd prints for these commands
// (bgp_show_peer, vty_show_route_map_entry, community_list_show), cut to
// the fields the check reads plus a few it ignores.

const neighborsGood = `{
  "192.0.2.10": {"remoteAs": 64512, "localAs": 64512, "nbrInternalLink": true, "bgpState": "Active",
    "addressFamilyInfo": {"ipv4Unicast": {"inboundPathPolicyConfig": true, "routeMapForIncomingAdvertisements": "packeteer-in", "acceptedPrefixCounter": 0}}},
  "192.0.2.20": {"remoteAs": 64511, "localAs": 64512, "nbrExternalLink": true, "bgpState": "Active",
    "addressFamilyInfo": {"ipv4Unicast": {"outboundPathPolicyConfig": true, "routeMapForOutgoingAdvertisements": "ebgp-out"}}}
}`

const packeteerIn = `{"packeteer-in": {"invoked": 0, "disabledOptimization": false, "processedChange": false, "rules": [
  {"sequenceNumber": 10, "type": "permit", "invoked": 0, "matchClauses": ["community packeteer"], "setClauses": [], "action": "Exit routemap"},
  {"sequenceNumber": 100, "type": "deny", "invoked": 0, "matchClauses": [], "setClauses": [], "action": "Exit routemap"}]}}`

const ebgpOut = `{"ebgp-out": {"invoked": 0, "disabledOptimization": false, "processedChange": false, "rules": [
  {"sequenceNumber": 10, "type": "deny", "invoked": 0, "matchClauses": ["community packeteer"], "setClauses": [], "action": "Exit routemap"},
  {"sequenceNumber": 100, "type": "permit", "invoked": 0, "matchClauses": [], "setClauses": [], "action": "Exit routemap"}]}}`

// ebgpOutBroken is the same route-map without the deny.
const ebgpOutBroken = `{"ebgp-out": {"invoked": 0, "disabledOptimization": false, "processedChange": false, "rules": [
  {"sequenceNumber": 100, "type": "permit", "invoked": 0, "matchClauses": [], "setClauses": [], "action": "Exit routemap"}]}}`

const listGood = "Named Community standard list packeteer\n    permit 64512:666\n"

type reply struct {
	out string
	st  byte
}

func good() map[string]reply {
	return map[string]reply{
		"show bgp neighbors json":                        {out: neighborsGood},
		"enable":                                         {},
		"show route-map packeteer-in json":               {out: packeteerIn},
		"show route-map ebgp-out json":                   {out: ebgpOut},
		"show bgp community-list packeteer detail":       {out: listGood},
		"show bgp large-community-list packeteer detail": {st: 1, out: "% Can't find large-community-list\n"},
	}
}

// fakeBGPD answers on one end of a pipe the way bgpd's vty socket does and
// records each command it received.
type fakeBGPD struct {
	mu  sync.Mutex
	got []string
}

func (f *fakeBGPD) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.got...)
}

func serve(t *testing.T, replies map[string]reply) (*session, *fakeBGPD) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	f := &fakeBGPD{}
	go func() {
		r := bufio.NewReader(server)
		for {
			cmd, err := r.ReadString(0)
			if err != nil {
				return
			}
			cmd = strings.TrimSuffix(cmd, "\x00")
			f.mu.Lock()
			f.got = append(f.got, cmd)
			f.mu.Unlock()
			rep, ok := replies[cmd]
			if !ok {
				rep = reply{out: "% Unknown command: " + cmd + "\n", st: 2}
			}
			if _, err := server.Write(append([]byte(rep.out), 0, 0, 0, rep.st)); err != nil {
				return
			}
		}
	}()
	return &session{w: client, r: bufio.NewReader(client)}, f
}

var q = plugin.FilterQuery{Community: "64512:666", Packeteer: netip.MustParseAddr("192.0.2.10")}

func run(t *testing.T, replies map[string]reply, query plugin.FilterQuery) ([]plugin.FilterFinding, *fakeBGPD) {
	t.Helper()
	s, f := serve(t, replies)
	got, err := check(s, query)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.commands() {
		if err := allow.Check(c); err != nil {
			t.Errorf("sent %q: %v", c, err)
		}
	}
	return got, f
}

func verdicts(fs []plugin.FilterFinding) string {
	var v []string
	for _, f := range fs {
		v = append(v, string(f.Verdict))
	}
	return strings.Join(v, ",")
}

func TestGoodFiltersPass(t *testing.T) {
	got, f := run(t, good(), q)
	if verdicts(got) != "pass,pass" {
		t.Fatalf("findings = %+v", got)
	}
	if !strings.Contains(got[0].Detail, "Import from Packeteer 192.0.2.10 (ipv4 unicast): route-map packeteer-in permits only routes with 64512:666") {
		t.Errorf("import detail = %q", got[0].Detail)
	}
	if !strings.Contains(got[1].Detail, "eBGP neighbor 192.0.2.20 (ipv4 unicast): route-map ebgp-out denies 64512:666 at entry 10") {
		t.Errorf("export detail = %q", got[1].Detail)
	}
	want := []string{"show bgp neighbors json", "enable", "show route-map packeteer-in json", "show bgp community-list packeteer detail", "show route-map ebgp-out json"}
	if strings.Join(f.commands(), "|") != strings.Join(want, "|") {
		t.Errorf("commands = %q, want %q", f.commands(), want)
	}
}

func TestMissingEBGPDenyFailsWithTheFix(t *testing.T) {
	r := good()
	r["show route-map ebgp-out json"] = reply{out: ebgpOutBroken}
	got, _ := run(t, r, q)
	if verdicts(got) != "pass,fail" {
		t.Fatalf("findings = %+v", got)
	}
	for _, want := range []string{"route-map ebgp-out", "sequence number below 100", "match community packeteer", "64512:666"} {
		if !strings.Contains(got[1].Fix, want) {
			t.Errorf("fix %q lacks %q", got[1].Fix, want)
		}
	}
	if !strings.Contains(got[1].Detail, "entry 100 permits before 64512:666 is denied") {
		t.Errorf("detail = %q", got[1].Detail)
	}
}

func TestPolicyCases(t *testing.T) {
	cases := []struct {
		name    string
		edit    func(map[string]reply)
		want    string
		snippet string // in the detail of the last finding that is not a pass
	}{
		{"no outbound route-map", func(r map[string]reply) {
			r["show bgp neighbors json"] = reply{out: strings.Replace(neighborsGood, `"routeMapForOutgoingAdvertisements": "ebgp-out"`, `"x": 1`, 1)}
		}, "pass,fail", "no outbound route-map"},
		{"ebgp-requires-policy holds everything back", func(r map[string]reply) {
			r["show bgp neighbors json"] = reply{out: strings.Replace(neighborsGood, `"routeMapForOutgoingAdvertisements": "ebgp-out"`, `"outboundEbgpRequiresPolicy": "Advertisements suppressed due to missing policy"`, 1)}
		}, "pass,pass", ""},
		{"no inbound route-map", func(r map[string]reply) {
			r["show bgp neighbors json"] = reply{out: strings.Replace(neighborsGood, `"routeMapForIncomingAdvertisements": "packeteer-in", `, ``, 1)}
		}, "fail,pass", "every route from Packeteer is accepted"},
		{"import permits without the community", func(r map[string]reply) {
			r["show route-map packeteer-in json"] = reply{out: strings.Replace(packeteerIn, `"matchClauses": ["community packeteer"]`, `"matchClauses": ["ip address prefix-list any"]`, 1)}
		}, "fail,pass", "entry 10 permits routes without 64512:666"},
		{"community list also permits another value", func(r map[string]reply) {
			r["show bgp community-list packeteer detail"] = reply{out: listGood + "    permit 64512:1\n"}
		}, "fail,pass", "permits routes without"},
		{"community list missing", func(r map[string]reply) {
			r["show bgp community-list packeteer detail"] = reply{out: "% Can't find community-list\n", st: 1}
		}, "fail,fail", "never permits 64512:666"},
		{"route-map calls another", func(r map[string]reply) {
			r["show route-map packeteer-in json"] = reply{out: strings.Replace(packeteerIn, `"setClauses": [], "action"`, `"setClauses": [], "callClause": "other", "action"`, 1)}
		}, "unknown,pass", "calls route-map other"},
		{"expanded list", func(r map[string]reply) {
			r["show bgp community-list packeteer detail"] = reply{out: "Named Community expanded list packeteer\n    permit 64512:6.*\n"}
		}, "unknown,unknown", "expanded list packeteer"},
		{"route-map not defined", func(r map[string]reply) { r["show route-map ebgp-out json"] = reply{out: "{}"} }, "pass,unknown", "applied but not defined"},
		{"Packeteer is not a neighbor", func(r map[string]reply) {
			r["show bgp neighbors json"] = reply{out: strings.Replace(neighborsGood, "192.0.2.10", "192.0.2.11", 1)}
		}, "fail,pass", "no BGP neighbor 192.0.2.10"},
		{"export continues on a match", func(r map[string]reply) {
			r["show route-map ebgp-out json"] = reply{out: strings.Replace(ebgpOut, `"action": "Exit routemap"`, `"action": "Continue to next entry"`, 1)}
		}, "pass,unknown", "continues on a match"},
		{"a name the allowlist refuses is not sent", func(r map[string]reply) {
			r["show bgp neighbors json"] = reply{out: strings.Replace(neighborsGood, `"ebgp-out"`, `"ebgp out\u0000configure terminal"`, 1)}
		}, "pass,unknown", "is not read"},
		{"no eBGP neighbor", func(r map[string]reply) {
			r["show bgp neighbors json"] = reply{out: `{"192.0.2.10": {"nbrInternalLink": true, "addressFamilyInfo": {"ipv4Unicast": {"routeMapForIncomingAdvertisements": "packeteer-in"}}}, "vrfName": "default"}`}
		}, "pass,pass", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := good()
			c.edit(r)
			got, f := run(t, r, q)
			if verdicts(got) != c.want {
				t.Fatalf("findings = %+v, want %s", got, c.want)
			}
			for _, g := range got {
				if g.Verdict == plugin.VerdictFail && g.Fix == "" {
					t.Errorf("failing finding without a fix: %+v", g)
				}
				if g.Verdict != plugin.VerdictFail && g.Fix != "" {
					t.Errorf("fix on a %s finding: %+v", g.Verdict, g)
				}
			}
			if c.snippet != "" && !strings.Contains(verdictDetails(got), c.snippet) {
				t.Errorf("details %q lack %q", verdictDetails(got), c.snippet)
			}
			for _, cmd := range f.commands() {
				if strings.Contains(cmd, "configure") {
					t.Errorf("sent %q", cmd)
				}
			}
		})
	}
}

func verdictDetails(fs []plugin.FilterFinding) string {
	var d []string
	for _, f := range fs {
		d = append(d, f.Detail)
	}
	return strings.Join(d, "\n")
}

func TestLargeCommunity(t *testing.T) {
	r := good()
	r["show route-map packeteer-in json"] = reply{out: strings.Replace(packeteerIn, "community packeteer", "large-community packeteer", 1)}
	r["show route-map ebgp-out json"] = reply{out: strings.Replace(ebgpOut, "community packeteer", "large-community packeteer", 1)}
	r["show bgp large-community-list packeteer detail"] = reply{out: "Named large community standard list packeteer\n    permit 65536:666:1\n"}
	got, f := run(t, r, plugin.FilterQuery{Community: "65536:666:1", Packeteer: q.Packeteer})
	if verdicts(got) != "pass,pass" {
		t.Fatalf("findings = %+v", got)
	}
	for _, c := range f.commands() {
		if c == "show bgp community-list packeteer detail" {
			t.Error("read the standard list for a large community")
		}
	}
}

// Every command off the allowlist is refused before a byte reaches the
// router: no configure, write, copy, clear, or a show smuggling one.
func TestNonReadCommandsAreRefused(t *testing.T) {
	s, f := serve(t, good())
	for _, cmd := range []string{
		"configure terminal", "configure", "conf t", "write memory", "write terminal", "write file", "copy running-config startup-config",
		"clear bgp *", "clear ip bgp 192.0.2.20", "no router bgp 64512", "router bgp 64512", "disable", "end", "exit",
		"show running-config", "show bgp neighbors json\nconfigure terminal", "show bgp neighbors json\x00write memory",
		"show route-map x json\nwrite", "show route-map a b json", "enable password lab", "", " ",
	} {
		if _, _, err := s.run(cmd); !errors.Is(err, readonly.ErrRefused) {
			t.Errorf("%q = %v, want ErrRefused", cmd, err)
		}
		if _, _, err := s.show(cmd); !errors.Is(err, readonly.ErrRefused) {
			t.Errorf("show %q = %v, want ErrRefused", cmd, err)
		}
	}
	// show enters the enable node once for the refused commands above, and
	// nothing else reached the router.
	if got := f.commands(); len(got) != 1 || got[0] != "enable" {
		t.Fatalf("the router received %q", got)
	}
}

func TestReadErrors(t *testing.T) {
	s, _ := serve(t, map[string]reply{"show bgp neighbors json": {out: "% bgpd is not running\n", st: 1}})
	if _, err := check(s, q); err == nil || !strings.Contains(err.Error(), "answered 1") {
		t.Fatalf("status 1 = %v", err)
	}
	s, _ = serve(t, map[string]reply{"show bgp neighbors json": {out: "not json"}})
	if _, err := check(s, q); err == nil {
		t.Fatal("a reply that is not JSON was read")
	}
}

func TestNewAndCheckFiltersKeepThePathSecret(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "lab-bgpd.vty")
	env := func(k string) string {
		if k == "PK_FRR" {
			return sock
		}
		return ""
	}
	cfg, _ := plugin.ConfigFromYAML("socket_env: PK_FRR")
	rc, err := New(cfg, plugin.Env{Getenv: env})
	if err != nil {
		t.Fatal(err)
	}
	_, err = rc.CheckFilters(context.Background(), q)
	if err == nil || strings.Contains(err.Error(), "lab-bgpd") || !strings.Contains(err.Error(), "connect to the router socket") {
		t.Fatalf("CheckFilters with no router = %v", err)
	}

	// A real socket: the full exchange over a unix connection.
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("no unix sockets here:", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		replies := good()
		for {
			cmd, err := r.ReadString(0)
			if err != nil {
				return
			}
			rep := replies[strings.TrimSuffix(cmd, "\x00")]
			if _, err := c.Write(append([]byte(rep.out), 0, 0, 0, rep.st)); err != nil {
				return
			}
		}
	}()
	got, err := rc.CheckFilters(context.Background(), q)
	if err != nil || verdicts(got) != "pass,pass" {
		t.Fatalf("CheckFilters = %+v, %v", got, err)
	}

	for _, bad := range []string{"", "socket_env: PK_UNSET", "socket_env: PK_FRR\nsocket: /x"} {
		cfg, _ := plugin.ConfigFromYAML(bad)
		if _, err := New(cfg, plugin.Env{Getenv: env}); err == nil {
			t.Errorf("New(%q) accepted", bad)
		}
	}
	cfg, _ = plugin.ConfigFromYAML("socket_env: PK_UNSET")
	if _, err := New(cfg, plugin.Env{Getenv: env, CheckOnly: true}); err != nil {
		t.Errorf("check only with the variable unset: %v", err)
	}
}
