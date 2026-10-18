package icmp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// nagiosDoc follows IXP Manager's customers foil: blank lines inside the
// object, a ping service that is only "use" plus host_name, an opted-out
// host with check_command null and no service, and a hostgroup whose
// members line is wrapped. service_description and check_command on a
// service do not grant Can Ping.
const nagiosDoc = `
# define host {
#     host_name commented
#     address 192.0.2.99
# }
#
# VLAN id: 10; protocol: ipv4; tag: 100; name: Peering.
#

### Host: 192.0.2.20 / member-a.example / Peering.

define host {
    use                     ixp-manager-member-host

    host_name               member-a-as64496-ipv4-vlanid10-vliid1

    alias                   Member A / sw1 / Peering VLAN #1.
    address                 192.0.2.20

}

### Service: 192.0.2.20 / member-a.example / Peering.

define service {
    use                     ixp-manager-member-ping-service

    host_name               member-a-as64496-ipv4-vlanid10-vliid1

}

### Host: 192.0.2.30 / member-b.example / Peering.

define host {
    use                     ixp-manager-member-host

    host_name               member-b-as64497-ipv4-vlanid10-vliid2

    alias                   Member B / sw1 / Peering VLAN #1.
    address                 192.0.2.30

    ## 'canping' is set to false for this vlan interface, disabling host check:
    check_command           null
}

### Service: 192.0.2.30 / member-b.example / Peering.

# canping disabled for this, skipping service ping check

### Host: 192.0.2.21 / member-c.example / Peering.

define host {
    use                     ixp-manager-member-host

    host_name               member-c-as64498-ipv4-vlanid10-vliid3

    alias                   Member C / sw1 / Peering VLAN #1.
    address                 192.0.2.21

}

### Service: 192.0.2.21 / member-c.example / Peering.

define service {
    use                     ixp-manager-member-ping-busy-service

    host_name               member-c-as64498-ipv4-vlanid10-vliid3

}

define host {
    host_name               described-only
    address                 192.0.2.41
}
define service {
    use                     ixp-manager-member-service
    host_name               described-only
    service_description     PING
    check_command           check_ping!250.0,20%!500.0,60%
}
define host {
    host_name               legacy
    address                 192.0.2.40
}
define service {
    host_name               legacy
    service_description     PING-Busy
    check_command           check_ping!100.0,10%!1500.0,50%
}

### Host: 2001:db8::20 / member-v6.example / Peering.

define host {
    use                     ixp-manager-member-host

    host_name               member-v6

    address                 2001:db8::20

}

define service {
    use                     ixp-manager-member-ping-service

    host_name               member-v6

}

define hostgroup {
    hostgroup_name  switch-ipv4-vlanid-10-sw1

    alias           All IPv4 Members Connected to Switch sw1 for VLAN Peering

    members         member-a-as64496-ipv4-vlanid10-vliid1, \
        member-c-as64498-ipv4-vlanid10-vliid3

}
`

func TestParseNagios(t *testing.T) {
	hosts, err := parseNagios([]byte(nagiosDoc))
	if err != nil {
		t.Fatal(err)
	}
	a := hosts["192.0.2.20"]
	if !a.canPing || a.busy {
		t.Fatalf("member-a %+v", a)
	}
	b, ok := hosts["192.0.2.30"]
	if !ok || b.canPing || b.busy {
		t.Fatalf("opted-out host %+v present %v", b, ok)
	}
	if hosts["192.0.2.41"].canPing {
		t.Fatal("service_description PING without the ping template was allowed")
	}
	if hosts["192.0.2.40"].canPing || hosts["192.0.2.40"].busy {
		t.Fatal("PING-Busy description without the busy template was allowed")
	}
	if _, ok := hosts["192.0.2.99"]; ok {
		t.Fatal("commented host was parsed")
	}
	c := hosts["192.0.2.21"]
	if !c.canPing || !c.busy {
		t.Fatalf("busy %+v", c)
	}
	v6 := hosts["2001:db8::20"]
	if !v6.canPing || v6.busy {
		t.Fatalf("v6 %+v", v6)
	}
	if len(hosts) != 6 {
		t.Fatalf("hosts %d", len(hosts))
	}
	empty, err := parseNagios([]byte("# nothing\n"))
	if err != nil || len(empty) != 0 {
		t.Fatalf("comment-only %+v %v", empty, err)
	}
	if _, err := parseNagios([]byte("<html><body>login</body></html>")); err == nil || !strings.Contains(err.Error(), "not a nagios config") {
		t.Fatalf("html %v", err)
	}
	can, busy := pingTemplate("ixp-manager-member-ping-service-extra")
	if can || busy {
		t.Fatal("a longer template name matched the ping service")
	}
}

func TestNagiosURL(t *testing.T) {
	got, err := nagiosURL("https://ixp.example/ixpm/api/v4/member-export/ixf/1.0?ignore_missing_ixfid=1", 10, "ipv4")
	if err != nil || got != "https://ixp.example/ixpm/admin/api/v4/nagios/customers/10/4" {
		t.Fatalf("%s %v", got, err)
	}
	got, err = nagiosURL("https://ixp.example/api/v4/member-export/ixf/1.0", 2, "ipv6")
	if err != nil || got != "https://ixp.example/admin/api/v4/nagios/customers/2/6" {
		t.Fatalf("%s %v", got, err)
	}
	for _, raw := range []string{
		"https://user:pass@ixp.example/api/v4/member-export/ixf/1.0",
		"https://ixp.example/members.json",
		"https://ixp.example/api/v4/nagios/customers/10/4",
		"ftp://ixp.example/api/v4/member-export/ixf/1.0",
	} {
		if _, err := nagiosURL(raw, 10, "ipv4"); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if _, err := nagiosURL("https://ixp.example/api/v4/member-export/ixf/1.0", 10, "4"); err == nil {
		t.Fatal("accepted a protocol digit as the family")
	}
}

func TestNagiosFetchAndOptOut(t *testing.T) {
	secret := "SuperSecretValue99"
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		if r.URL.RawQuery != "" {
			t.Errorf("query %s", r.URL.RawQuery)
		}
		if strings.Contains(r.URL.String(), secret) {
			t.Errorf("url contains the key")
		}
		if r.Header.Get("X-IXP-Manager-API-Key") != secret {
			t.Errorf("header %q", r.Header.Get("X-IXP-Manager-API-Key"))
		}
		switch r.URL.Path {
		case "/ixpm/admin/api/v4/nagios/customers/10/4":
			_, _ = io.WriteString(w, nagiosDoc)
		default:
			t.Errorf("path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	fp := &fakeProber{res: plugin.ProbeResult{Sent: 1, RTTs: []time.Duration{300 * time.Millisecond}}}
	r := testRunner(fp)
	r.apiKey = secret
	r.workers = 2
	off := v4("192.0.2.30")
	on := v4("192.0.2.20")
	busy := v4("192.0.2.21")
	view := memberView([]plugin.IXPMember{oneMember(64496, "Member A", on, off, busy)})
	view.Manager = true
	view.URL = srv.URL + "/ixpm/api/v4/member-export/ixf/1.0?ignore_missing_ixfid=1"
	r.setMembers(func() plugin.MemberView { return view })
	r.setVantages([]plugin.FabricVantage{vantage("lan1-v4", "192.0.2.8")})
	r.runRound(context.Background())
	if hits != 1 {
		t.Fatalf("hits %d", hits)
	}
	got := r.snapshot()
	if got.OptOut != 1 || got.Targets != 2 || got.Error != "" || got.Stale {
		t.Fatalf("%+v", got)
	}
	reqs := fp.requests()
	if len(reqs) != 2 {
		t.Fatalf("probes %d", len(reqs))
	}
	byTarget := map[string]plugin.ProbeRequest{}
	for _, req := range reqs {
		byTarget[req.Target.String()] = req
		if req.Provider != "lan1-v4" || req.Source.String() != "192.0.2.8" || req.Count != 5 {
			t.Fatalf("request %+v", req)
		}
	}
	if _, ok := byTarget["192.0.2.30"]; ok {
		t.Fatal("opt-out address was probed")
	}
	if byTarget["192.0.2.20"].Timeout != time.Second {
		t.Fatalf("normal timeout %s", byTarget["192.0.2.20"].Timeout)
	}
	if byTarget["192.0.2.21"].Timeout != tolBusy.critRTT {
		t.Fatalf("busy timeout %s", byTarget["192.0.2.21"].Timeout)
	}
	for _, s := range got.Samples {
		if s.Address == "192.0.2.21" && (!s.BusyHost || s.PastTolerance) {
			t.Fatalf("busy sample %+v", s)
		}
		if s.Address == "192.0.2.20" && (s.BusyHost || !s.PastTolerance || s.LossPct != 0) {
			t.Fatalf("normal sample %+v", s)
		}
	}

	// A later failure keeps the opt-out.
	hits = 0
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, secret)
	}))
	defer fail.Close()
	view.URL = fail.URL + "/api/v4/member-export/ixf/1.0"
	fp.reqs = nil
	r.runRound(context.Background())
	got = r.snapshot()
	if hits != 1 || got.OptOut != 1 || fp.count() != 2 || !strings.Contains(got.Error, "HTTP 500") || strings.Contains(got.Error, secret) {
		t.Fatalf("hits %d probes %d view %+v", hits, fp.count(), got)
	}
	if _, ok := r.parts["ipv4/10"]; !ok {
		t.Fatalf("policy dropped %+v", r.parts)
	}
}

func TestNagiosUnauthorizedAndRedirect(t *testing.T) {
	secret := "SuperSecretValue99"
	body := "<html>" + secret + "</html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RequestURI(), secret) {
			t.Errorf("request target contains the key")
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	fp := &fakeProber{}
	r := testRunner(fp)
	r.apiKey = secret
	addr := v4("192.0.2.20")
	view := memberView([]plugin.IXPMember{oneMember(64496, "Member A", addr)})
	view.Manager = true
	view.URL = srv.URL + "/api/v4/member-export/ixf/1.0"
	r.setMembers(func() plugin.MemberView { return view })
	r.setVantages([]plugin.FabricVantage{vantage("lan1-v4", "192.0.2.8")})
	r.runRound(context.Background())
	got := r.snapshot()
	if fp.count() != 0 || got.OptOut != 1 || got.Targets != 0 || !strings.Contains(got.Error, "HTTP 401") || strings.Contains(got.Error, secret) {
		t.Fatalf("probes %d view %+v", fp.count(), got)
	}

	fp.reqs = nil
	addr.CanPing = boolPtr(false)
	view.Members[0].Connections[0].Addresses[0] = addr
	r.runRound(context.Background())
	got = r.snapshot()
	if fp.count() != 0 || got.OptOut != 1 || strings.Contains(got.Error, secret) {
		t.Fatalf("opt-out probes %d view %+v", fp.count(), got)
	}

	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/elsewhere", http.StatusFound)
	}))
	defer redir.Close()
	addr.CanPing = nil
	view.Members[0].Connections[0].Addresses[0] = addr
	view.URL = redir.URL + "/api/v4/member-export/ixf/1.0"
	fp.reqs = nil
	r.parts = nil
	r.runRound(context.Background())
	got = r.snapshot()
	if !strings.Contains(got.Error, "redirects are not followed") || strings.Contains(got.Error, secret) || fp.count() != 0 || got.Targets != 0 {
		t.Fatalf("probes %d view %+v", fp.count(), got)
	}

	// The key must not be fetched even if a caller builds a URL that contains it.
	var called bool
	blocked := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer blocked.Close()
	if _, err := r.getNagios(context.Background(), blocked.URL+"/?k="+secret); err == nil || !strings.Contains(err.Error(), "must not contain") || called {
		t.Fatalf("called %v err %v", called, err)
	}
}

// A failed Can Ping fetch keeps the last list for policyStaleIntervals
// intervals. After that the list is not used and the VLAN is not probed,
// even though the member address was probed on the last good list.
func TestNagiosListExpires(t *testing.T) {
	var fail bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, nagiosDoc)
	}))
	defer srv.Close()

	now := time.Unix(100, 0).UTC()
	fp := &fakeProber{res: plugin.ProbeResult{Sent: 1, RTTs: []time.Duration{300 * time.Millisecond}}}
	r := testRunner(fp)
	r.now = func() time.Time { return now }
	on := v4("192.0.2.20")
	view := memberView([]plugin.IXPMember{oneMember(64496, "Member A", on)})
	view.Manager = true
	view.URL = srv.URL + "/ixpm/api/v4/member-export/ixf/1.0"
	r.setMembers(func() plugin.MemberView { return view })
	r.setVantages([]plugin.FabricVantage{vantage("lan1-v4", "192.0.2.8")})

	r.runRound(context.Background())
	if fp.count() != 1 {
		t.Fatalf("good list probes %d", fp.count())
	}

	fail = true
	now = now.Add(2 * time.Minute)
	fp.reqs = nil
	r.runRound(context.Background())
	got := r.snapshot()
	if fp.count() != 1 || got.Targets != 1 || !strings.Contains(got.Error, "HTTP 401") {
		t.Fatalf("list inside the limit: probes %d view %+v", fp.count(), got)
	}

	now = now.Add(time.Minute + time.Second)
	fp.reqs = nil
	r.runRound(context.Background())
	got = r.snapshot()
	if fp.count() != 0 || got.Targets != 0 || got.OptOut != 1 || !strings.Contains(got.Error, "HTTP 401") {
		t.Fatalf("expired list: probes %d view %+v", fp.count(), got)
	}

	fail = false
	fp.reqs = nil
	r.runRound(context.Background())
	if fp.count() != 1 {
		t.Fatalf("after recovery probes %d", fp.count())
	}
}

func TestNagiosBodyCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("a"), nagiosMaxBytes+1))
	}))
	defer srv.Close()
	r := testRunner(&fakeProber{})
	if _, err := r.getNagios(context.Background(), srv.URL); err == nil || !strings.Contains(err.Error(), "max_bytes") {
		t.Fatal(err)
	}
}

func TestNamedIXFDoesNotFetchNagios(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()
	fp := &fakeProber{}
	r := testRunner(fp)
	off := v4("192.0.2.30")
	off.CanPing = boolPtr(false)
	view := memberView([]plugin.IXPMember{oneMember(64496, "Member A", v4("192.0.2.20"), off)})
	view.Manager = false
	view.URL = srv.URL + "/members.json"
	r.setMembers(func() plugin.MemberView { return view })
	r.setVantages([]plugin.FabricVantage{vantage("lan1-v4", "192.0.2.8")})
	r.runRound(context.Background())
	got := r.snapshot()
	if hits != 0 || got.Targets != 1 || got.OptOut != 1 || fp.count() != 1 {
		t.Fatalf("hits %d probes %d view %+v", hits, fp.count(), got)
	}
}

func TestRoundFailClosed(t *testing.T) {
	fp := &fakeProber{}
	var log bytes.Buffer
	r := testRunner(fp)
	r.log = slog.New(slog.NewTextHandler(&log, nil))
	r.setVantages([]plugin.FabricVantage{vantage("lan1-v4", "192.0.2.8")})
	r.publish(plugin.FabricView{Configured: true, Targets: 1, Samples: []plugin.FabricSample{{Address: "192.0.2.20", RTTMs: 4}}})

	r.setMembers(func() plugin.MemberView { return plugin.MemberView{Configured: true} })
	r.runRound(context.Background())
	got := r.snapshot()
	if !got.Stale || got.Error != "member list has not loaded" || len(got.Samples) != 0 || fp.count() != 0 {
		t.Fatalf("%+v probes %d", got, fp.count())
	}

	stale := memberView([]plugin.IXPMember{oneMember(64496, "Member A", v4("192.0.2.20"))})
	stale.Stale = true
	stale.Error = "member list is stale"
	r.setMembers(func() plugin.MemberView { return stale })
	r.runRound(context.Background())
	got = r.snapshot()
	if !got.Stale || len(got.Samples) != 0 || got.Targets != 0 || fp.count() != 0 || got.Error != "member list is stale" {
		t.Fatalf("%+v", got)
	}

	fresh := memberView([]plugin.IXPMember{oneMember(64496, "Member A", v4("192.0.2.20"))})
	fresh.Error = "temporary refresh failure"
	r.setMembers(func() plugin.MemberView { return fresh })
	r.runRound(context.Background())
	got = r.snapshot()
	if got.Stale || got.Error != "" || got.Targets != 1 || fp.count() != 1 {
		t.Fatalf("non-stale error stopped the round: %+v probes %d", got, fp.count())
	}

	fp.err = errors.New("bind 192.0.2.8: cannot assign requested address")
	fp.reqs = nil
	r.runRound(context.Background())
	got = r.snapshot()
	if len(got.Samples) != 1 || got.Samples[0].Error == "" || got.Samples[0].PastTolerance || got.Samples[0].Sent != 0 || got.Vantages[0].Up || got.Vantages[0].Error == "" {
		t.Fatalf("%+v", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := got
	r.runRound(ctx)
	if r.snapshot().Samples[0].Error != before.Samples[0].Error || fp.count() != 1 {
		t.Fatal("cancelled round published")
	}

	if strings.Count(log.String(), "ixp fabric round") < 1 || strings.Contains(log.String(), "192.0.2.20") {
		t.Fatalf("log\n%s", log.String())
	}
}

func TestRateLimitsBlockTheNextProbe(t *testing.T) {
	view := memberView([]plugin.IXPMember{oneMember(64496, "Member A", v4("192.0.2.20"), v4("192.0.2.21"))})
	fp := &fakeProber{}
	first := make(chan struct{})
	var once sync.Once
	fp.onDone = func(n int) {
		if n == 1 {
			once.Do(func() { close(first) })
		}
	}
	r := testRunner(fp)
	r.workers = 2
	r.packets = 5
	member := &seqWait{blockOn: 2, hold: make(chan struct{}), hit: make(chan struct{})}
	r.memberWait = func(asn uint32) waiter {
		if asn != 64496 {
			t.Errorf("asn %d", asn)
		}
		return member
	}
	r.global = allowWait{}
	r.setMembers(func() plugin.MemberView { return view })
	r.setVantages([]plugin.FabricVantage{vantage("lan1-v4", "192.0.2.8")})
	done := make(chan struct{})
	go func() {
		r.runRound(context.Background())
		close(done)
	}()
	select {
	case <-member.hit:
	case <-t.Context().Done():
		t.Fatal("member limiter did not block")
	}
	select {
	case <-first:
	case <-t.Context().Done():
		t.Fatal("first probe did not finish")
	}
	if fp.count() != 1 {
		t.Fatalf("probes while the second member wait blocked: %d", fp.count())
	}
	close(member.hold)
	select {
	case <-done:
	case <-t.Context().Done():
		t.Fatal("round did not finish")
	}
	if fp.count() != 2 || member.calls != 2 || member.ns[0] != 5 {
		t.Fatalf("probes %d calls %d ns %v", fp.count(), member.calls, member.ns)
	}

	fp2 := &fakeProber{}
	first = make(chan struct{})
	once = sync.Once{}
	fp2.onDone = func(n int) {
		if n == 1 {
			once.Do(func() { close(first) })
		}
	}
	r.prober = fp2
	global := &seqWait{blockOn: 2, hold: make(chan struct{}), hit: make(chan struct{})}
	r.global = global
	r.memberWait = func(uint32) waiter { return allowWait{} }
	two := memberView([]plugin.IXPMember{
		oneMember(64496, "Member A", v4("192.0.2.20")),
		oneMember(64497, "Member B", v4("192.0.2.21")),
	})
	r.setMembers(func() plugin.MemberView { return two })
	done = make(chan struct{})
	go func() {
		r.runRound(context.Background())
		close(done)
	}()
	select {
	case <-global.hit:
	case <-t.Context().Done():
		t.Fatal("global limiter did not block")
	}
	select {
	case <-first:
	case <-t.Context().Done():
		t.Fatal("first global probe did not finish")
	}
	if fp2.count() != 1 {
		t.Fatalf("probes while the global wait blocked: %d", fp2.count())
	}
	close(global.hold)
	select {
	case <-done:
	case <-t.Context().Done():
		t.Fatal("global round did not finish")
	}
	if fp2.count() != 2 {
		t.Fatalf("probes %d", fp2.count())
	}

	var waits int
	r.memberWait = func(uint32) waiter {
		return fnWait{fn: func(context.Context, int) error { waits++; return nil }}
	}
	r.global = fnWait{fn: func(context.Context, int) error { waits++; return nil }}
	off := v4("192.0.2.20")
	off.CanPing = boolPtr(false)
	r.setMembers(func() plugin.MemberView {
		return memberView([]plugin.IXPMember{oneMember(64496, "Member A", off)})
	})
	fp3 := &fakeProber{}
	r.prober = fp3
	r.runRound(context.Background())
	if waits != 0 || fp3.count() != 0 || r.snapshot().OptOut != 1 {
		t.Fatalf("waits %d probes %d view %+v", waits, fp3.count(), r.snapshot())
	}
}

func TestMemberLimiterEvictsAndPolicyDrops(t *testing.T) {
	fp := &fakeProber{}
	r := testRunner(fp)
	r.memberWait = nil
	r.memberPPS = 1
	r.packets = 5
	r.global = allowWait{}
	r.setVantages([]plugin.FabricVantage{vantage("lan1-v4", "192.0.2.8")})
	r.setMembers(func() plugin.MemberView {
		return memberView([]plugin.IXPMember{oneMember(64496, "Member A", v4("192.0.2.20"))})
	})
	r.runRound(context.Background())
	if _, ok := r.memberLim[64496]; !ok || len(r.memberLim) != 1 {
		t.Fatalf("limiters %+v", r.memberLim)
	}
	r.setMembers(func() plugin.MemberView {
		return memberView([]plugin.IXPMember{oneMember(64497, "Member B", v4("192.0.2.21"))})
	})
	r.runRound(context.Background())
	if _, ok := r.memberLim[64496]; ok || len(r.memberLim) != 1 {
		t.Fatalf("limiters after leave %+v", r.memberLim)
	}

	var vlan int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if vlan == 10 && r.URL.Path != "/admin/api/v4/nagios/customers/10/4" {
			t.Errorf("path %s", r.URL.Path)
		}
		if vlan == 11 && r.URL.Path != "/admin/api/v4/nagios/customers/11/4" {
			t.Errorf("path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, "# empty\n")
	}))
	defer srv.Close()
	view := memberView(nil)
	view.Manager = true
	view.URL = srv.URL + "/api/v4/member-export/ixf/1.0"
	view.IXPs[0].VLANs = append(view.IXPs[0].VLANs, plugin.IXPVLAN{ID: 11, IPv4: "198.51.100.0/24"})
	vlan = 10
	r.setMembers(func() plugin.MemberView { return view })
	r.setVantages([]plugin.FabricVantage{vantage("lan1-v4", "192.0.2.8")})
	r.runRound(context.Background())
	if _, ok := r.parts["ipv4/10"]; !ok {
		t.Fatalf("parts %+v", r.parts)
	}
	vlan = 11
	r.setVantages([]plugin.FabricVantage{{Name: "lan2-v4", VLANID: 11, Address: netip.MustParseAddr("198.51.100.8")}})
	r.runRound(context.Background())
	if _, ok := r.parts["ipv4/10"]; ok {
		t.Fatalf("old policy kept %+v", r.parts)
	}
	if _, ok := r.parts["ipv4/11"]; !ok {
		t.Fatalf("new policy missing %+v", r.parts)
	}
}

func TestStopCancelsABlockedProbe(t *testing.T) {
	cfg, err := plugin.ConfigFromYAML("interval: 1m\npackets: 1\nrate_limit_pps: 10\nmember_pps: 1\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	pr := p.(*Prober)
	if pr.r.interval != time.Minute || pr.r.packets != 1 || pr.r.workers != DefaultWorkers {
		t.Fatalf("defaults not applied: interval %s packets %d workers %d", pr.r.interval, pr.r.packets, pr.r.workers)
	}
	fp := &fakeProber{entered: make(chan struct{}), block: make(chan struct{})}
	pr.r.prober = fp
	pr.r.global = allowWait{}
	pr.r.memberWait = func(uint32) waiter { return allowWait{} }
	pr.SetMembers(func() plugin.MemberView {
		return memberView([]plugin.IXPMember{oneMember(64496, "Member A", v4("192.0.2.20"))})
	})
	pr.SetVantages([]plugin.FabricVantage{vantage("lan1-v4", "192.0.2.8")})
	if err := pr.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-fp.entered:
	case <-t.Context().Done():
		t.Fatal("probe did not start")
	}
	stopCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := pr.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
	if fp.count() != 1 {
		t.Fatalf("probes %d", fp.count())
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	for _, y := range []string{
		"interval: 1s\n",
		"timeout: 10s\n",
		"packets: 21\n",
		"workers: 65\n",
		"rate_limit_pps: 1\nmember_pps: 2\n",
		"nope: 1\n",
	} {
		cfg, err := plugin.ConfigFromYAML(y)
		if err != nil {
			t.Fatalf("%s: %v", y, err)
		}
		if _, err := New(cfg, plugin.Env{CheckOnly: true}); err == nil {
			t.Fatalf("accepted %s", y)
		}
	}
	cfg, err := plugin.ConfigFromYAML("")
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if !p.View().Configured || len(p.View().Samples) != 0 {
		t.Fatalf("%+v", p.View())
	}
}
