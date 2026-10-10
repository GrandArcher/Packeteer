package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
)

// The form sections (#130) merge into the YAML, and the merged text goes
// through the editor's checks, which are the controller's start checks:
// config.Parse, the environment, and preflight (every plugin's config and
// the cross-checks). Nothing here may turn inject on.
func TestFormSectionsPassStartChecks(t *testing.T) {
	ed, path := editorFor(t, uiBase)
	form, err := configedit.ParseForm([]byte(uiBase))
	if err != nil {
		t.Fatal(err)
	}
	form.Flow.Enabled = true
	form.Flow.Listen = []string{"127.0.0.1:2055"}
	form.Flow.TopN = "20"
	form.Flow.MinPct = "1"
	form.Policies.Rules = []configedit.FormRule{
		{Name: "pin", Action: "static", Providers: []string{"transit-a"}, Prefixes: []string{"203.0.113.0/24"}, MaxLossPct: "1"},
		{Name: "vips", Action: "vip", Prefixes: []string{"198.51.100.0/24"}},
	}
	form.VIP.Enabled = true
	form.VIP.Interval = "10s"
	form.VIP.Prefixes = []configedit.FormTarget{{Prefix: "198.51.100.0/24"}}
	form.Outage.Enabled = true
	form.Outage.MinPrefixes = "3"
	form.Outage.Interval = "5s"
	merged, err := configedit.ApplyForm([]byte(uiBase), form)
	if err != nil {
		t.Fatal(err)
	}
	res := ed.Check(merged)
	if !res.Valid || res.Mode != config.ModeObserve || res.EnablesInject {
		t.Fatalf("check: %+v\n%s", res, merged)
	}
	// Same path as the page: save with the file's hash. No confirm_inject
	// is needed because nothing turned inject on, and the file loads.
	if _, res, err := ed.Save(merged, configedit.Hash([]byte(uiBase)), false); err != nil || !res.Valid {
		t.Fatalf("save: %v %+v", err, res)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Sources) != 3 || len(cfg.Policies) != 1 || cfg.Mode != config.ModeObserve {
		t.Fatalf("sources %d policies %d mode %s", len(cfg.Sources), len(cfg.Policies), cfg.Mode)
	}
}

// The loader's cross-checks still refuse what the form lets through.
func TestFormSectionsLoaderChecksStillApply(t *testing.T) {
	ed, _ := editorFor(t, uiBase)
	for name, tc := range map[string]struct {
		edit func(*configedit.Form)
		want string
	}{
		"flow tail": {func(f *configedit.Form) {
			f.Flow.Enabled = true
			f.Flow.Listen = []string{"127.0.0.1:2055"}
			f.Flow.TopN = "10"
			f.Flow.MaxTargets = "20"
		}, "tail_interval"},
		"flow tail inside probe interval": {func(f *configedit.Form) {
			f.Flow.Enabled = true
			f.Flow.Listen = []string{"127.0.0.1:2055"}
			f.Flow.TopN = "10"
			f.Flow.MaxTargets = "20"
			f.Flow.TailInterval = "1s"
		}, "tail_interval"},
		"rule with a country and no database": {func(f *configedit.Form) {
			f.Policies.Rules = []configedit.FormRule{{Action: "ignore", Countries: []string{"ZZ"}}}
		}, "geoip"},
		"vip slower than the staleness window": {func(f *configedit.Form) {
			f.VIP.Enabled = true
			f.VIP.Interval = "24h"
			f.VIP.Prefixes = []configedit.FormTarget{{Prefix: "198.51.100.0/24"}}
		}, "interval"},
		"outage slower than probing": {func(f *configedit.Form) {
			f.Outage.Enabled = true
			f.Outage.Interval = "24h"
		}, "interval"},
	} {
		form, _ := configedit.ParseForm([]byte(uiBase))
		tc.edit(&form)
		merged, err := configedit.ApplyForm([]byte(uiBase), form)
		if err != nil {
			t.Errorf("%s: form refused it first: %v", name, err)
			continue
		}
		res := ed.Check(merged)
		if res.Valid || !strings.Contains(strings.Join(res.Errors, "\n"), tc.want) {
			t.Errorf("%s: %+v, want %q", name, res, tc.want)
		}
	}
}

// A form edit that sets inject still needs confirm_inject on Save, and a
// section edit alone never sets it.
func TestFormSectionsNeverEnableInjectUnconfirmed(t *testing.T) {
	ed, path := editorFor(t, uiBase)
	before, _ := os.ReadFile(path)
	form, _ := configedit.ParseForm([]byte(uiBase))
	form.Mode = "inject"
	form.Flow.Enabled = true
	form.Flow.Listen = []string{"127.0.0.1:2055"}
	merged, err := configedit.ApplyForm([]byte(uiBase), form)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ed.Save(merged, configedit.Hash(before), false); err == nil {
		t.Fatal("inject saved without confirmation")
	} else if !errors.Is(err, configedit.ErrConfirmInject) && !errors.Is(err, configedit.ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("file changed")
	}
}

// The wizard's optional flow step renders an observe config with an empty
// allowlist and no announcer, and the start checks (the same as -check)
// accept it.
func TestWizardFlowPassesStartChecks(t *testing.T) {
	ed, _ := editorFor(t, uiBase)
	out, err := configedit.Wizard(configedit.WizardInput{
		ASN: 64512, RouterID: "192.0.2.10", Edge: "192.0.2.254",
		Providers: []configedit.WizardProvider{{Name: "transit-a", SourceIP: "192.0.2.11", NextHop: "192.0.2.1"}},
		Prefix:    "198.51.100.0/24",
		Flow:      &configedit.WizardFlow{Listen: "0.0.0.0:2055"},
	})
	if err != nil {
		t.Fatal(err)
	}
	res := ed.Check(out)
	if !res.Valid || res.Mode != config.ModeObserve {
		t.Fatalf("check: %+v\n%s", res, out)
	}
	cfg, err := config.Parse(out)
	if err != nil || cfg.Mode != config.ModeObserve || len(cfg.Allowlist.Prefixes) != 0 || cfg.Announcer != nil {
		t.Fatalf("wizard flow can announce: %v %+v", err, cfg)
	}
}
