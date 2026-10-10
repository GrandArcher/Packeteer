package announce

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/policy"
)

// bindAnn is an announcer that publishes on a speaker it is bound to.
type bindAnn struct {
	fakeAnn
	binds     int
	community string
	err       error
}

func (b *bindAnn) Bind(_ any, community string) error {
	if b.err != nil {
		return b.err
	}
	b.binds++
	b.community = community
	return nil
}

func observeCtl(t *testing.T, ann *bindAnn, mutate func(*Config)) *Controller {
	t.Helper()
	cfg := testCfg()
	cfg.Mode = "observe"
	if mutate != nil {
		mutate(&cfg)
	}
	rib := memRIB{ready: true, has: map[netip.Prefix]bool{
		pfx("198.51.100.0/24"): true,
		pfx("203.0.113.0/24"):  true,
	}}
	c, err := New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A controller that starts in observe binds on the first switch to inject,
// announces only after the switch, withdraws everything on the switch back,
// and announces nothing in between.
func TestApplyRuntimeObserveToInjectToObserve(t *testing.T) {
	ctx := context.Background()
	ann := &bindAnn{}
	c := observeCtl(t, ann, nil)
	c.RememberSpeaker(struct{}{})
	imps := []policy.Improvement{imp("198.51.100.0/24", "b")}
	allow := []netip.Prefix{pfx("198.51.100.0/24")}

	if err := c.Sync(ctx, imps); err != nil || ann.count() != 0 || ann.binds != 0 {
		t.Fatalf("observe: err %v routes %d binds %d", err, ann.count(), ann.binds)
	}
	// Prepare checks and binds but does not change the mode.
	if err := c.PrepareRuntime("inject", 50); err != nil {
		t.Fatal(err)
	}
	if ann.binds != 1 || ann.community != "64512:666" {
		t.Fatalf("binds %d community %q", ann.binds, ann.community)
	}
	if err := c.Sync(ctx, imps); err != nil || ann.count() != 0 {
		t.Fatalf("after prepare: err %v routes %d (the mode has not changed)", err, ann.count())
	}
	if err := c.ApplyRuntime(ctx, "inject", allow, 50); err != nil {
		t.Fatal(err)
	}
	if ann.binds != 1 {
		t.Fatalf("binds = %d, want the one from Prepare", ann.binds)
	}
	if err := c.Sync(ctx, imps); err != nil || ann.count() != 1 || c.Active() != 1 {
		t.Fatalf("inject: err %v routes %d active %d", err, ann.count(), c.Active())
	}
	// The new allowlist applies: 203.0.113.0/24 is not in it.
	if err := c.Sync(ctx, []policy.Improvement{imp("198.51.100.0/24", "b"), imp("203.0.113.0/24", "b")}); err == nil || !strings.Contains(err.Error(), "not allowlisted") || ann.count() != 1 {
		t.Fatalf("allowlist: err %v routes %d", err, ann.count())
	}
	// Back to observe withdraws at once and a later Sync announces nothing.
	if err := c.ApplyRuntime(ctx, "observe", allow, 50); err != nil {
		t.Fatal(err)
	}
	if ann.count() != 0 || ann.all != 1 || c.Active() != 0 {
		t.Fatalf("observe: routes %d withdraw-all %d active %d", ann.count(), ann.all, c.Active())
	}
	if err := c.Sync(ctx, imps); err != nil || ann.count() != 0 {
		t.Fatalf("observe again: err %v routes %d", err, ann.count())
	}
	// And to inject again without a second bind.
	if err := c.ApplyRuntime(ctx, "inject", allow, 50); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, imps); err != nil || ann.count() != 1 || ann.binds != 1 {
		t.Fatalf("inject again: err %v routes %d binds %d", err, ann.count(), ann.binds)
	}
}

// A switch to inject that cannot bind leaves the mode, allowlist, and cap
// as they were, and nothing is announced.
func TestApplyRuntimeBindFailureKeepsMode(t *testing.T) {
	ctx := context.Background()
	imps := []policy.Improvement{imp("198.51.100.0/24", "b")}
	allow := []netip.Prefix{pfx("198.51.100.0/24")}

	for name, tc := range map[string]struct {
		speaker bool
		ann     *bindAnn
		want    string
	}{
		"no speaker":     {false, &bindAnn{}, "iBGP session"},
		"bind refused":   {true, &bindAnn{err: errors.New("bind refused")}, "bind refused"},
		"no bind method": {true, nil, ""},
	} {
		t.Run(name, func(t *testing.T) {
			var c *Controller
			if tc.ann != nil {
				c = observeCtl(t, tc.ann, nil)
			} else {
				cfg := testCfg()
				cfg.Mode = "observe"
				var err error
				if c, err = New(cfg, &fakeAnn{}, memRIB{ready: true}, nil); err != nil {
					t.Fatal(err)
				}
				tc.want = "cannot publish"
			}
			if tc.speaker {
				c.RememberSpeaker(struct{}{})
			}
			if err := c.PrepareRuntime("inject", 7); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("PrepareRuntime: %v, want %q", err, tc.want)
			}
			if err := c.ApplyRuntime(ctx, "inject", allow, 7); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ApplyRuntime: %v, want %q", err, tc.want)
			}
			if c.cfg.Mode != "observe" || len(c.cfg.Allowlist) != 3 || c.cfg.MaxImprovements != 50 {
				t.Fatalf("state changed: mode %q allowlist %v cap %d", c.cfg.Mode, c.cfg.Allowlist, c.cfg.MaxImprovements)
			}
			if err := c.Sync(ctx, imps); err != nil || c.Routes() != 0 {
				t.Fatalf("sync: err %v routes %d", err, c.Routes())
			}
		})
	}
}

// Entering inject runs the checks New skips in observe.
func TestApplyRuntimeRunsInjectChecks(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"local_pref":          {func(c *Config) { c.LocalPref = 0 }, "local_pref"},
		"community":           {func(c *Config) { c.Community = "" }, "community"},
		"bad community":       {func(c *Config) { c.Community = "not-a-community" }, "community"},
		"provider local_pref": {func(c *Config) { c.ProviderLocalPref = map[string]uint32{"a": 0} }, "local_pref"},
		"as_path":             {func(c *Config) { c.ASPath = "native" }, "as_path"},
		"more_specific cap":   {func(c *Config) { c.MoreSpecific = true }, "max_routes"},
	} {
		t.Run(name, func(t *testing.T) {
			ann := &bindAnn{}
			c := observeCtl(t, ann, tc.mutate)
			c.RememberSpeaker(struct{}{})
			if err := c.PrepareRuntime("inject", 50); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("PrepareRuntime: %v, want %q", err, tc.want)
			}
			if err := c.ApplyRuntime(ctx, "inject", nil, 50); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ApplyRuntime: %v, want %q", err, tc.want)
			}
			if ann.binds != 0 || c.cfg.Mode != "observe" {
				t.Fatalf("binds %d mode %q after a refused check", ann.binds, c.cfg.Mode)
			}
		})
	}
	// No announcer at all.
	cfg := testCfg()
	cfg.Mode = "observe"
	c, err := New(cfg, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.RememberSpeaker(struct{}{})
	if err := c.ApplyRuntime(ctx, "inject", nil, 50); err == nil || !strings.Contains(err.Error(), "announcer") {
		t.Fatalf("no announcer: %v", err)
	}
}

// A running inject controller takes a new cap and allowlist; PrepareRuntime
// for the mode it is already in changes nothing.
func TestApplyRuntimeCapAndAllowlistInInject(t *testing.T) {
	ctx := context.Background()
	ann := &bindAnn{}
	cfg := testCfg()
	rib := memRIB{ready: true, has: map[netip.Prefix]bool{pfx("198.51.100.0/24"): true, pfx("203.0.113.0/24"): true}}
	c, err := New(cfg, ann, rib, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Bind(struct{}{}); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareRuntime("inject", 1); err != nil || ann.binds != 1 {
		t.Fatalf("prepare in inject: %v binds %d", err, ann.binds)
	}
	imps := []policy.Improvement{imp("198.51.100.0/24", "b"), imp("203.0.113.0/24", "b")}
	if err := c.ApplyRuntime(ctx, "inject", cfg.Allowlist, 1); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, imps); err == nil || !strings.Contains(err.Error(), "max_improvements (1)") || c.Active() != 1 {
		t.Fatalf("cap 1: err %v active %d", err, c.Active())
	}
	// A narrower allowlist: the decision engine retires the prefix it no
	// longer covers, and Sync withdraws it.
	if err := c.ApplyRuntime(ctx, "inject", []netip.Prefix{pfx("203.0.113.0/24")}, 1); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx, imps[1:]); err != nil {
		t.Fatal(err)
	}
	if _, ok := ann.routes[pfx("198.51.100.0/24")]; ok || c.Active() != 1 {
		t.Fatalf("routes %v active %d", ann.routes, c.Active())
	}
}

func TestRememberSpeakerIgnoresNil(t *testing.T) {
	ann := &bindAnn{}
	c := observeCtl(t, ann, nil)
	c.RememberSpeaker(nil)
	if c.srv != nil {
		t.Fatal("a nil speaker was remembered")
	}
	var nilCtl *Controller
	nilCtl.RememberSpeaker(struct{}{})
	if err := nilCtl.PrepareRuntime("inject", 1); err != nil {
		t.Fatal(err)
	}
}
