package main

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/plugins/announcer/gobgp"
	"github.com/GrandArcher/Packeteer/internal/plugins/exec"
	"github.com/GrandArcher/Packeteer/internal/plugins/notifier/webhook"
	"github.com/GrandArcher/Packeteer/internal/plugins/policy/maintenance"
	"github.com/GrandArcher/Packeteer/internal/plugins/policy/rules"
	"github.com/GrandArcher/Packeteer/internal/plugins/prober/fixed"
	"github.com/GrandArcher/Packeteer/internal/plugins/prober/icmp"
	"github.com/GrandArcher/Packeteer/internal/plugins/prober/tcp"
	"github.com/GrandArcher/Packeteer/internal/plugins/prober/udp"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/commit"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/cost"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/flow"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/outage"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/static"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/traceroute"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/vip"
	telemetryfixed "github.com/GrandArcher/Packeteer/internal/plugins/telemetry/fixed"
	"github.com/GrandArcher/Packeteer/internal/plugins/telemetry/snmp"
)

// TestConfigDocCoversStructs fails when a yaml tag on a config struct, or an
// environment variable the controller reads, is missing from docs/CONFIG.md.
func TestConfigDocCoversStructs(t *testing.T) {
	doc, err := os.ReadFile("../../docs/CONFIG.md")
	if err != nil {
		t.Fatalf("read docs/CONFIG.md: %v", err)
	}
	text := string(doc)

	var missing []string
	for _, key := range yamlKeys(
		config.Config{},
		icmp.Config{},
		tcp.Config{},
		udp.Config{},
		fixed.Config{},
		fixed.PathSpec{},
		static.Config{},
		static.Target{},
		flow.Config{},
		traceroute.Config{},
		outage.Config{},
		vip.Config{},
		snmp.Config{},
		telemetryfixed.Config{},
		telemetryfixed.Provider{},
		weighted.Config{},
		commit.Config{},
		cost.Config{},
		cost.Floor{},
		webhook.Config{},
		exec.Config{},
		gobgp.Config{},
		rules.Config{},
		rules.Rule{},
		maintenance.Config{},
		maintenance.Window{},
	) {
		if !strings.Contains(text, "`"+key+"`") {
			missing = append(missing, key)
		}
	}
	for _, env := range []string{
		ConfigEnv, PluginDirEnv, LogLevelEnv, LogFormatEnv, HTTPListenEnv, HTTPUserEnv, HTTPPassEnv,
	} {
		if !strings.Contains(text, "`"+env+"`") {
			missing = append(missing, env)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("docs/CONFIG.md is missing %s", strings.Join(missing, ", "))
	}
	if !strings.Contains(text, "gobgp") {
		t.Fatal("docs/CONFIG.md does not document the gobgp announcer")
	}
}

func yamlKeys(values ...any) []string {
	seen := map[string]bool{}
	var keys []string
	var walk func(reflect.Type)
	walk = func(t reflect.Type) {
		if t == nil {
			return
		}
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			return
		}
		if t.PkgPath() == "gopkg.in/yaml.v3" {
			return
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" && !f.Anonymous {
				continue
			}
			if name, ok := yamlName(f.Tag.Get("yaml")); ok && !seen[name] {
				seen[name] = true
				keys = append(keys, name)
			}
			ft := f.Type
			for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice || ft.Kind() == reflect.Array {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				walk(ft)
			}
		}
	}
	for _, v := range values {
		walk(reflect.TypeOf(v))
	}
	return keys
}

func yamlName(tag string) (string, bool) {
	if tag == "" || tag == "-" {
		return "", false
	}
	name := strings.Split(tag, ",")[0]
	if name == "" || name == "-" {
		return "", false
	}
	return name, true
}
