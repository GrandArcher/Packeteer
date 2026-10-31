package main

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/plugins/announcer/gobgp"
	"github.com/GrandArcher/Packeteer/internal/plugins/detector/baseline"
	"github.com/GrandArcher/Packeteer/internal/plugins/elector/lease"
	"github.com/GrandArcher/Packeteer/internal/plugins/exec"
	"github.com/GrandArcher/Packeteer/internal/plugins/exporter/snmpagent"
	"github.com/GrandArcher/Packeteer/internal/plugins/federation/mtls"
	"github.com/GrandArcher/Packeteer/internal/plugins/grpcplugin"
	"github.com/GrandArcher/Packeteer/internal/plugins/inventory/invcommon"
	"github.com/GrandArcher/Packeteer/internal/plugins/inventory/netbox"
	"github.com/GrandArcher/Packeteer/internal/plugins/inventory/peeringmanager"
	irrfile "github.com/GrandArcher/Packeteer/internal/plugins/irr/file"
	irrwhois "github.com/GrandArcher/Packeteer/internal/plugins/irr/whois"
	coreicmp "github.com/GrandArcher/Packeteer/internal/plugins/ixpcore/icmp"
	"github.com/GrandArcher/Packeteer/internal/plugins/ixpcorrelate/topology"
	fabricicmp "github.com/GrandArcher/Packeteer/internal/plugins/ixpfabric/icmp"
	"github.com/GrandArcher/Packeteer/internal/plugins/ixprouteserver/birdseye"
	"github.com/GrandArcher/Packeteer/internal/plugins/leaksource/rislive"
	"github.com/GrandArcher/Packeteer/internal/plugins/lookup/peeringdb"
	"github.com/GrandArcher/Packeteer/internal/plugins/notifier/smtp"
	"github.com/GrandArcher/Packeteer/internal/plugins/notifier/snmptrap"
	"github.com/GrandArcher/Packeteer/internal/plugins/notifier/syslog"
	"github.com/GrandArcher/Packeteer/internal/plugins/notifier/webhook"
	"github.com/GrandArcher/Packeteer/internal/plugins/policy/maintenance"
	"github.com/GrandArcher/Packeteer/internal/plugins/policy/rules"
	"github.com/GrandArcher/Packeteer/internal/plugins/prober/fixed"
	"github.com/GrandArcher/Packeteer/internal/plugins/prober/icmp"
	"github.com/GrandArcher/Packeteer/internal/plugins/prober/tcp"
	"github.com/GrandArcher/Packeteer/internal/plugins/prober/udp"
	regpeeringdb "github.com/GrandArcher/Packeteer/internal/plugins/registry/peeringdb"
	regripe "github.com/GrandArcher/Packeteer/internal/plugins/registry/ripe"
	"github.com/GrandArcher/Packeteer/internal/plugins/ribsource/bmp"
	"github.com/GrandArcher/Packeteer/internal/plugins/rpki/rtr"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/commit"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/cost"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weights"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/flow"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/outage"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/span"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/static"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/traceroute"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/vip"
	"github.com/GrandArcher/Packeteer/internal/plugins/sso/oidc"
	"github.com/GrandArcher/Packeteer/internal/plugins/storage/sqlite"
	telemetryfixed "github.com/GrandArcher/Packeteer/internal/plugins/telemetry/fixed"
	"github.com/GrandArcher/Packeteer/internal/plugins/telemetry/snmp"
	"github.com/GrandArcher/Packeteer/internal/plugins/threatfeed/httpfeed"
	"github.com/GrandArcher/Packeteer/internal/plugins/whois/rdap"
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
		flow.ProblemsConfig{},
		flow.TransitConfig{},
		span.Config{},
		traceroute.Config{},
		outage.Config{},
		vip.Config{},
		snmp.Config{},
		telemetryfixed.Config{},
		telemetryfixed.Provider{},
		weighted.Config{},
		weights.Config{},
		commit.Config{},
		cost.Config{},
		cost.Floor{},
		webhook.Config{},
		smtp.Config{},
		snmptrap.Config{},
		syslog.Config{},
		snmpagent.Config{},
		exec.Config{},
		grpcplugin.Config{},
		gobgp.Config{},
		gobgp.InboundConfig{},
		gobgp.InboundProvider{},
		gobgp.MitigationConfig{},
		gobgp.MitigationBlackholeCfg{},
		gobgp.MitigationRedirectCfg{},
		rules.Config{},
		rules.Rule{},
		maintenance.Config{},
		maintenance.Window{},
		sqlite.Config{},
		rdap.Config{},
		bmp.Config{},
		bmp.LeakConfig{},
		rislive.Config{},
		mtls.Config{},
		mtls.Peer{},
		lease.Config{},
		oidc.Config{},
		baseline.Config{},
		httpfeed.Config{},
		rtr.Config{},
		irrwhois.Config{},
		irrfile.Config{},
		fabricicmp.Config{},
		birdseye.Config{},
		birdseye.ServerConfig{},
		topology.Config{},
		topology.Bundle{},
		coreicmp.Config{},
		config.CoreLink{},
		peeringdb.Config{},
		regpeeringdb.Config{},
		regripe.Config{},
		config.Registry{},
		config.RegistryIRR{},
		invcommon.Common{},
	) {
		if !strings.Contains(text, "`"+key+"`") {
			missing = append(missing, key)
		}
	}
	for _, env := range []string{
		ConfigEnv, PluginDirEnv, LogLevelEnv, LogFormatEnv, HTTPListenEnv, HTTPUserEnv, HTTPPassEnv, lease.IDEnv, peeringdb.APIKeyEnv, netbox.TokenEnv, peeringmanager.TokenEnv, AdminUserEnv, AdminPassEnv,
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
