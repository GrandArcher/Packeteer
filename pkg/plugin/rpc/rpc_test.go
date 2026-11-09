package rpc

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// all implements every kind and records what it was given.
type all struct {
	cfg     struct{ Name string }
	gotReq  plugin.ProbeRequest
	gotEvt  plugin.Event
	failMsg string
}

func (a *all) Init(_ context.Context, req InitRequest) error {
	return req.DecodeConfig(&a.cfg)
}

func (a *all) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	a.gotReq = req
	if a.failMsg != "" {
		return plugin.ProbeResult{}, errors.New(a.failMsg)
	}
	return plugin.ProbeResult{Sent: 2, RTTs: []time.Duration{1500 * time.Microsecond}}, nil
}

func (a *all) Targets(context.Context) ([]plugin.Target, error) {
	return []plugin.Target{{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Host: netip.MustParseAddr("203.0.113.9"), Weight: 3}}, nil
}

func (a *all) Notify(_ context.Context, e plugin.Event) error {
	a.gotEvt = e
	return nil
}

// probeOnly implements the base interface and Prober only.
type probeOnly struct{ all }

func (probeOnly) Targets() {}
func (probeOnly) Notify()  {}

// serve starts impl on a loopback listener and returns a client for it.
func serve(t *testing.T, impl Plugin) *Client {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	srv.RegisterService(&serviceDesc, &server{impl: impl})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &Client{conn: conn}
}

func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	impl := &all{}
	c := serve(t, impl)

	init := func(kind plugin.Kind) error {
		return c.Init(ctx, InitRequest{Kind: kind, Name: "x", Config: []byte(`{"name":"edge1"}`)})
	}

	if err := init(plugin.KindProber); err != nil {
		t.Fatal(err)
	}
	if impl.cfg.Name != "edge1" {
		t.Fatalf("config = %+v", impl.cfg)
	}
	req := plugin.ProbeRequest{Provider: "transit-a", Source: netip.MustParseAddr("192.0.2.11"), Target: netip.MustParseAddr("2001:db8::1"),
		Count: 4, Timeout: 1500 * time.Millisecond, Mark: 0xdeadbeef, DSCP: 46}
	res, err := c.Probe(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if impl.gotReq != req {
		t.Fatalf("plugin saw %+v, want %+v", impl.gotReq, req)
	}
	if res.Sent != 2 || len(res.RTTs) != 1 || res.RTTs[0] != 1500*time.Microsecond {
		t.Fatalf("result = %+v", res)
	}

	// A plugin error keeps its message and is not a transport failure.
	impl.failMsg = "no route to source"
	_, err = c.Probe(ctx, req)
	if st, _ := status.FromError(err); st.Code() == codes.Unavailable || !strings.Contains(st.Message(), "no route to source") {
		t.Fatalf("plugin error = %v", err)
	}

	if err := init(plugin.KindSource); err != nil {
		t.Fatal(err)
	}
	tg, err := c.Targets(ctx)
	if err != nil || len(tg) != 1 || tg[0].Host.String() != "203.0.113.9" || tg[0].Weight != 3 {
		t.Fatalf("targets = %+v, %v", tg, err)
	}

	if err := init(plugin.KindNotifier); err != nil {
		t.Fatal(err)
	}
	ev := plugin.Event{Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Kind: plugin.EventBGPSessionDown, Severity: plugin.SeverityCritical,
		Message: "neighbor 192.0.2.1 down", Fields: map[string]string{"neighbor": "192.0.2.1"}}
	if err := c.Notify(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if !impl.gotEvt.Time.Equal(ev.Time) || impl.gotEvt.Kind != ev.Kind || impl.gotEvt.Severity != ev.Severity ||
		impl.gotEvt.Message != ev.Message || impl.gotEvt.Fields["neighbor"] != "192.0.2.1" {
		t.Fatalf("plugin saw %+v, want %+v", impl.gotEvt, ev)
	}
}

func TestKindChecks(t *testing.T) {
	ctx := context.Background()

	// A plugin refuses a kind it does not implement, and any kind beyond
	// the three: an announcer cannot be requested.
	c := serve(t, &probeOnly{})
	for kind, want := range map[plugin.Kind]string{
		plugin.KindSource:    "cannot run as a source",
		plugin.KindNotifier:  "cannot run as a notifier",
		plugin.KindAnnouncer: `kind "announcer" is not supported`,
		plugin.KindScorer:    `kind "scorer" is not supported`,
	} {
		err := c.Init(ctx, InitRequest{Kind: kind})
		if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), want) {
			t.Errorf("init as %s = %v, want %q", kind, err, want)
		}
	}

	// Calls need an Init of the same kind first.
	c = serve(t, &all{})
	if _, err := c.Probe(ctx, plugin.ProbeRequest{Source: netip.MustParseAddr("192.0.2.1"), Target: netip.MustParseAddr("192.0.2.2")}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("probe before init = %v", err)
	}
	if err := c.Init(ctx, InitRequest{Kind: plugin.KindSource}); err != nil {
		t.Fatal(err)
	}
	if err := c.Notify(ctx, plugin.Event{Kind: plugin.EventBGPSessionDown}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("notify on a source = %v", err)
	}
}

func TestDecodeConfig(t *testing.T) {
	var v struct{ A int }
	if err := (InitRequest{}).DecodeConfig(&v); err != nil {
		t.Fatalf("absent config: %v", err)
	}
	if err := (InitRequest{Config: []byte("null")}).DecodeConfig(&v); err != nil {
		t.Fatalf("null config: %v", err)
	}
	if err := (InitRequest{Config: []byte(`{"A":3}`)}).DecodeConfig(&v); err != nil || v.A != 3 {
		t.Fatalf("A = %d, %v", v.A, err)
	}
	if err := (InitRequest{Config: []byte(`{"A":3,"B":1}`)}).DecodeConfig(&v); err == nil || !strings.Contains(err.Error(), `unknown field "B"`) {
		t.Fatalf("unknown field = %v", err)
	}
}

// plugin.proto is the contract for plugins in other languages: it must name
// the same service and methods the Go server registers.
func TestProtoMatchesService(t *testing.T) {
	b, err := os.ReadFile("plugin.proto")
	if err != nil {
		t.Fatal(err)
	}
	proto := string(b)
	pkg := regexp.MustCompile(`(?m)^package ([\w.]+);`).FindStringSubmatch(proto)
	svc := regexp.MustCompile(`(?m)^service (\w+) \{`).FindStringSubmatch(proto)
	if pkg == nil || svc == nil || pkg[1]+"."+svc[1] != serviceName {
		t.Fatalf("proto service = %v %v, want %s", pkg, svc, serviceName)
	}
	var inProto []string
	for _, m := range regexp.MustCompile(`(?m)^\s*rpc (\w+)\(google\.protobuf\.Struct\) returns \(google\.protobuf\.Struct\);`).FindAllStringSubmatch(proto, -1) {
		inProto = append(inProto, m[1])
	}
	var inGo []string
	for _, m := range serviceDesc.Methods {
		inGo = append(inGo, m.MethodName)
	}
	slices.Sort(inProto)
	slices.Sort(inGo)
	if !slices.Equal(inProto, inGo) {
		t.Fatalf("proto methods %v, server methods %v", inProto, inGo)
	}
}
