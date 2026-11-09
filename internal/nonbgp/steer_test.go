package nonbgp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fakeRouter is a router whose route table holds only tagged routes.
type fakeRouter struct {
	plugin.Base
	mu         sync.Mutex
	routes     map[netip.Prefix]netip.Addr
	installs   int
	removes    int
	listErr    error
	removeErr  error
	installErr error
}

func newFakeRouter() *fakeRouter {
	return &fakeRouter{routes: map[netip.Prefix]netip.Addr{}}
}

func (f *fakeRouter) Install(_ context.Context, r plugin.SteerRoute) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.installErr != nil {
		return f.installErr
	}
	f.installs++
	f.routes[r.Prefix] = r.NextHop
	return nil
}

func (f *fakeRouter) Remove(_ context.Context, p netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.removeErr != nil {
		return f.removeErr
	}
	f.removes++
	delete(f.routes, p)
	return nil
}

func (f *fakeRouter) Owned(context.Context) ([]netip.Prefix, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []netip.Prefix
	for p := range f.routes {
		out = append(out, p)
	}
	return out, nil
}

func (f *fakeRouter) has(p string) (netip.Addr, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	nh, ok := f.routes[pfx(p)]
	return nh, ok
}

func (f *fakeRouter) set(fn func()) {
	f.mu.Lock()
	fn()
	f.mu.Unlock()
}

type steerRig struct {
	r    *fakeRouter
	s    *Steer
	live map[netip.Prefix]bool
}

func newRig(t *testing.T, inject bool, max int) *steerRig {
	t.Helper()
	rig := &steerRig{r: newFakeRouter(), live: map[netip.Prefix]bool{}}
	for _, p := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8:1::/48", "2001:db8::/46", "198.51.100.0/25"} {
		rig.live[pfx(p)] = true
	}
	cfg := SteerConfig{
		Inject:    inject,
		Allowlist: []netip.Prefix{pfx("198.51.100.0/24"), pfx("203.0.113.0/24"), pfx("2001:db8::/32")},
		Max:       max,
		NextHops:  map[string]netip.Addr{"isp-a": addr("192.0.2.1"), "isp-b": addr("198.51.100.1"), "isp-b6": addr("2001:db8:ffff::1")},
		Live:      func(p netip.Prefix) bool { return rig.live[p] },
		Now:       func() time.Time { return time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC) },
	}
	var drv plugin.Steerer = rig.r
	s, err := NewSteer(cfg, drv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	rig.s = s
	return rig
}

func imp(p, provider string) policy.Improvement {
	return policy.Improvement{Prefix: pfx(p), Provider: provider, Native: "isp-a"}
}

func TestObserveNeverCallsTheSteerer(t *testing.T) {
	rig := newRig(t, false, 5)
	if err := rig.s.Sync(context.Background(), []policy.Improvement{imp("198.51.100.0/24", "isp-b")}); err != nil {
		t.Fatal(err)
	}
	if rig.r.installs != 0 || len(rig.s.Active()) != 0 {
		t.Fatalf("observe installed %d routes, tracked %d", rig.r.installs, len(rig.s.Active()))
	}
	rig.r.set(func() { rig.r.listErr = errors.New("must not be asked") })
	if err := rig.s.Sync(context.Background(), nil); err != nil {
		t.Fatalf("observe asked the router: %v", err)
	}
	var none *Steer
	if err := none.Sync(context.Background(), nil); err != nil || none.WithdrawAll(context.Background()) != nil || len(none.Active()) != 0 || none.Active() != nil {
		t.Fatal("a nil Steer is not inert")
	}
}

func TestInstallKeepSwitchAndRemove(t *testing.T) {
	rig := newRig(t, true, 5)
	ctx := context.Background()
	if err := rig.s.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "isp-b")}); err != nil {
		t.Fatal(err)
	}
	if nh, ok := rig.r.has("198.51.100.0/24"); !ok || nh != addr("198.51.100.1") {
		t.Fatalf("route = %s %v, want via the provider's gateway", nh, ok)
	}
	act := rig.s.Active()
	if len(act) != 1 || act[0].Provider != "isp-b" || act[0].NextHop != addr("198.51.100.1") {
		t.Fatalf("active = %+v", act)
	}
	since := act[0].Since

	// The same improvement again does not touch the router.
	if err := rig.s.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "isp-b")}); err != nil || rig.r.installs != 1 {
		t.Fatalf("keep: err %v installs %d", err, rig.r.installs)
	}
	// A switch to another provider replaces the route and keeps its age.
	if err := rig.s.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "isp-a")}); err != nil {
		t.Fatal(err)
	}
	if nh, _ := rig.r.has("198.51.100.0/24"); nh != addr("192.0.2.1") || rig.r.installs != 2 {
		t.Fatalf("switch: next hop %s installs %d", nh, rig.r.installs)
	}
	if got := rig.s.Active()[0]; !got.Since.Equal(since) || got.Provider != "isp-a" {
		t.Fatalf("switch lost the route's age: %+v", got)
	}
	// The improvement ends: the route goes, the default route carries the prefix again.
	if err := rig.s.Sync(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := rig.r.has("198.51.100.0/24"); ok || len(rig.s.Active()) != 0 {
		t.Fatal("the route stayed after its improvement ended")
	}
}

func TestInstallRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		im   policy.Improvement
		want string
	}{
		{"outside the allowlist", imp("192.0.2.0/24", "isp-b"), "outside the allowlist"},
		{"more specific than the floor", imp("198.51.100.0/25", "isp-b"), "never steered"},
		{"default route", imp("0.0.0.0/0", "isp-b"), "never steered"},
		{"unknown provider", imp("198.51.100.0/24", "isp-c"), "no next hop"},
		{"family mismatch", imp("2001:db8:1::/48", "isp-b"), "no next hop"},
	} {
		rig := newRig(t, true, 5)
		err := rig.s.Sync(context.Background(), []policy.Improvement{tc.im})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", tc.name, err, tc.want)
		}
		if rig.r.installs != 0 {
			t.Errorf("%s: the router was changed", tc.name)
		}
	}
	rig := newRig(t, true, 5)
	rig.live[pfx("203.0.113.0/24")] = false
	if err := rig.s.Sync(context.Background(), []policy.Improvement{imp("203.0.113.0/24", "isp-b")}); err == nil || !strings.Contains(err.Error(), "not a tracked synthetic prefix") || rig.r.installs != 0 {
		t.Fatalf("a prefix that is not live was steered: %v", err)
	}
}

func TestIPv6RouteUsesIPv6Gateway(t *testing.T) {
	rig := newRig(t, true, 5)
	if err := rig.s.Sync(context.Background(), []policy.Improvement{imp("2001:db8:1::/48", "isp-b6")}); err != nil {
		t.Fatal(err)
	}
	if nh, ok := rig.r.has("2001:db8:1::/48"); !ok || nh != addr("2001:db8:ffff::1") {
		t.Fatalf("v6 route = %s %v", nh, ok)
	}
}

func TestCapRefusesNewRoutes(t *testing.T) {
	rig := newRig(t, true, 1)
	ctx := context.Background()
	err := rig.s.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "isp-b"), imp("203.0.113.0/24", "isp-b")})
	if err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("err = %v, want a cap refusal", err)
	}
	if len(rig.s.Active()) != 1 || rig.r.installs != 1 {
		t.Fatalf("count %d installs %d, want 1", len(rig.s.Active()), rig.r.installs)
	}
	// Moving the one route to another provider is not a new route.
	if err := rig.s.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "isp-a")}); err != nil {
		t.Fatalf("a switch counted against the cap: %v", err)
	}
}

func TestAgedOutPrefixIsRemovedEvenWithItsImprovement(t *testing.T) {
	rig := newRig(t, true, 5)
	ctx := context.Background()
	imps := []policy.Improvement{imp("198.51.100.0/24", "isp-b")}
	if err := rig.s.Sync(ctx, imps); err != nil {
		t.Fatal(err)
	}
	rig.live[pfx("198.51.100.0/24")] = false
	err := rig.s.Sync(ctx, imps)
	if _, ok := rig.r.has("198.51.100.0/24"); ok || len(rig.s.Active()) != 0 {
		t.Fatal("a route for a prefix that left the table stayed on the router")
	}
	if err == nil {
		t.Fatal("the refused re-install was not reported")
	}
}

func TestFailedRemoveIsRetried(t *testing.T) {
	rig := newRig(t, true, 5)
	ctx := context.Background()
	if err := rig.s.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "isp-b")}); err != nil {
		t.Fatal(err)
	}
	rig.r.set(func() { rig.r.removeErr = errors.New("api unreachable") })
	if err := rig.s.Sync(ctx, nil); err == nil || !strings.Contains(err.Error(), "api unreachable") {
		t.Fatalf("err = %v", err)
	}
	if len(rig.s.Active()) != 1 {
		t.Fatal("a route that could not be removed was forgotten")
	}
	rig.r.set(func() { rig.r.removeErr = nil })
	if err := rig.s.Sync(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := rig.r.has("198.51.100.0/24"); ok || len(rig.s.Active()) != 0 {
		t.Fatal("the retry did not remove the route")
	}
}

func TestFailedInstallIsNotTracked(t *testing.T) {
	rig := newRig(t, true, 5)
	rig.r.set(func() { rig.r.installErr = errors.New("api unreachable") })
	err := rig.s.Sync(context.Background(), []policy.Improvement{imp("198.51.100.0/24", "isp-b")})
	if err == nil || len(rig.s.Active()) != 0 {
		t.Fatalf("err %v count %d", err, len(rig.s.Active()))
	}
}

func TestWithdrawAllLeavesForeignRoutes(t *testing.T) {
	rig := newRig(t, true, 5)
	ctx := context.Background()
	if err := rig.s.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "isp-b"), imp("203.0.113.0/24", "isp-a")}); err != nil {
		t.Fatal(err)
	}
	// A tagged route this process did not install is not its to remove.
	rig.r.set(func() { rig.r.routes[pfx("192.0.2.0/24")] = addr("198.51.100.1") })
	if err := rig.s.WithdrawAll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(rig.s.Active()) != 0 {
		t.Fatalf("count = %d", len(rig.s.Active()))
	}
	for _, p := range []string{"198.51.100.0/24", "203.0.113.0/24"} {
		if _, ok := rig.r.has(p); ok {
			t.Errorf("%s stayed after WithdrawAll", p)
		}
	}
	if _, ok := rig.r.has("192.0.2.0/24"); !ok {
		t.Error("WithdrawAll removed a route this process did not install")
	}
}

func TestFirstSyncSweepsLeftOvers(t *testing.T) {
	rig := newRig(t, true, 5)
	ctx := context.Background()
	// A crashed run left two routes: one is still wanted, one is not.
	rig.r.set(func() {
		rig.r.routes[pfx("203.0.113.0/24")] = addr("198.51.100.1")
		rig.r.routes[pfx("198.51.100.0/24")] = addr("198.51.100.1")
	})
	rig.r.set(func() { rig.r.listErr = errors.New("api unreachable") })
	err := rig.s.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "isp-b")})
	if err == nil || rig.r.installs != 0 {
		t.Fatalf("a sweep that could not list the router went on: err %v installs %d", err, rig.r.installs)
	}
	rig.r.set(func() { rig.r.listErr = nil })
	if err := rig.s.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "isp-b")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := rig.r.has("203.0.113.0/24"); ok {
		t.Error("the left-over route stayed")
	}
	if _, ok := rig.r.has("198.51.100.0/24"); !ok {
		t.Error("a wanted route was removed")
	}
	// The sweep runs once: a later foreign-tagged route is left for withdraw handling.
	removes := rig.r.removes
	rig.r.set(func() { rig.r.routes[pfx("192.0.2.0/24")] = addr("192.0.2.1") })
	if err := rig.s.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "isp-b")}); err != nil || rig.r.removes != removes {
		t.Fatalf("a later sync swept again: err %v removes %d->%d", err, removes, rig.r.removes)
	}
}

func TestNewSteerRefusesUnsafeInject(t *testing.T) {
	live := func(netip.Prefix) bool { return true }
	allow := []netip.Prefix{pfx("198.51.100.0/24")}
	for name, cfg := range map[string]SteerConfig{
		"no allowlist": {Inject: true, Live: live},
		"no table":     {Inject: true, Allowlist: allow},
	} {
		if _, err := NewSteer(cfg, newFakeRouter(), nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewSteer(SteerConfig{Inject: true, Allowlist: allow, Live: live}, nil, nil); err == nil {
		t.Error("inject without a steerer accepted")
	}
	if _, err := NewSteer(SteerConfig{}, nil, nil); err != nil {
		t.Errorf("observe without a steerer: %v", err)
	}
}
