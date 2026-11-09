package snmpagent

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/plugins/snmpcfg"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// mibDef is one named node of deploy/mib/PACKETEER-MIB.txt.
type mibDef struct {
	oid    []uint32
	kind   string
	access string
	parent string
}

var (
	defRe = regexp.MustCompile(`(?s)(\w+)\s+(OBJECT-TYPE|NOTIFICATION-TYPE|MODULE-IDENTITY|OBJECT-GROUP|NOTIFICATION-GROUP|MODULE-COMPLIANCE)\b(.*?)::=\s*\{\s*(\w+)((?:\s+\d+)*)\s*\}`)
	oidRe = regexp.MustCompile(`(\w+)\s+OBJECT IDENTIFIER\s*::=\s*\{\s*(\w+)((?:\s+\d+)+)\s*\}`)
	accRe = regexp.MustCompile(`MAX-ACCESS\s+(\S+)`)
	cmtRe = regexp.MustCompile(`--[^\n]*`)
)

// parseMIB reads the module without a MIB compiler: the definitions that
// end in `::= { parent n }`, resolved to numeric OIDs.
func parseMIB(t *testing.T) map[string]mibDef {
	t.Helper()
	raw, err := os.ReadFile("../../../../deploy/mib/PACKETEER-MIB.txt")
	if err != nil {
		t.Fatal(err)
	}
	text := cmtRe.ReplaceAllString(string(raw), "")
	// Past the IMPORTS list, which names the macros without defining them.
	text = text[strings.Index(text, "FROM SNMPv2-CONF;")+len("FROM SNMPv2-CONF;"):]
	type pending struct {
		def    mibDef
		parent string
		tail   string
	}
	raws := map[string]pending{}
	for _, m := range defRe.FindAllStringSubmatch(text, -1) {
		acc := ""
		if a := accRe.FindStringSubmatch(m[3]); a != nil {
			acc = a[1]
		}
		if _, dup := raws[m[1]]; dup {
			t.Fatalf("MIB node %s is defined twice", m[1])
		}
		raws[m[1]] = pending{mibDef{kind: m[2], access: acc, parent: m[4]}, m[4], m[5]}
	}
	for _, m := range oidRe.FindAllStringSubmatch(text, -1) {
		if _, dup := raws[m[1]]; dup {
			t.Fatalf("MIB node %s is defined twice", m[1])
		}
		raws[m[1]] = pending{mibDef{kind: "OBJECT IDENTIFIER", parent: m[2]}, m[2], m[3]}
	}
	defs := map[string]mibDef{}
	var resolve func(name string) []uint32
	resolve = func(name string) []uint32 {
		if name == "enterprises" {
			return []uint32{1, 3, 6, 1, 4, 1}
		}
		if d, ok := defs[name]; ok {
			return d.oid
		}
		p, ok := raws[name]
		if !ok {
			t.Fatalf("MIB node %s is used but not defined", name)
		}
		oid := slices.Clone(resolve(p.parent))
		for _, f := range strings.Fields(p.tail) {
			n, _ := parseOID(f)
			oid = append(oid, n...)
		}
		d := p.def
		d.oid = oid
		defs[name] = d
		return oid
	}
	for name := range raws {
		resolve(name)
	}
	return defs
}

func camelKind(kind string) string {
	var b strings.Builder
	b.WriteString("pktr")
	for _, p := range strings.FieldsFunc(kind, func(r rune) bool { return r == '.' || r == '_' }) {
		b.WriteString(strings.ToUpper(p[:1]) + p[1:])
	}
	return b.String()
}

func TestMIBMatchesTheAgentAndTheCatalog(t *testing.T) {
	defs := parseMIB(t)
	root := defs["packeteer"].oid
	if got := oidString(root); got != "."+snmpcfg.DefaultEnterpriseOID {
		t.Fatalf("the MIB is rooted at %s, not at the default enterprise_oid", got)
	}

	// Every readable object of the MIB, with its instances, is what a
	// fully populated agent serves, and nothing else.
	want := map[string]bool{}
	for _, d := range defs {
		if d.kind != "OBJECT-TYPE" || d.access != "read-only" {
			continue
		}
		if d.parent == "pktrProviderEntry" {
			want[oidString(append(slices.Clone(d.oid), 1))] = true
			want[oidString(append(slices.Clone(d.oid), 2))] = true
		} else {
			want[oidString(append(slices.Clone(d.oid), 0))] = true
		}
	}
	rate := 12.0
	got := map[string]bool{}
	for _, r := range buildView(root, fullSnapshot(), &rate).rows {
		got[oidString(r.oid)] = true
	}
	for o := range want {
		if !got[o] {
			t.Errorf("the MIB defines %s but the agent does not serve it", o)
		}
	}
	for o := range got {
		if !want[o] {
			t.Errorf("the agent serves %s, which the MIB does not define as read-only", o)
		}
	}

	// The event objects are the varbinds the snmptrap notifier sends.
	for i, name := range []string{"pktrEventKind", "pktrEventSeverity", "pktrEventMessage", "pktrEventTime", "pktrEventFields", "pktrEventDedupKey"} {
		if o := oidString(defs[name].oid); o != fmt.Sprintf(".%s.1.%d", snmpcfg.DefaultEnterpriseOID, i+1) || defs[name].access != "accessible-for-notify" {
			t.Errorf("%s is %s (%s)", name, o, defs[name].access)
		}
	}

	// One notification per event kind, numbered by trap_id.
	seen := map[uint32]string{}
	for _, s := range plugin.EventCatalog() {
		d, ok := defs[camelKind(s.Kind)]
		if !ok || d.kind != "NOTIFICATION-TYPE" {
			t.Errorf("event %s has no notification %s in the MIB", s.Kind, camelKind(s.Kind))
			continue
		}
		if o := oidString(d.oid); o != fmt.Sprintf(".%s.0.%d", snmpcfg.DefaultEnterpriseOID, s.TrapID) {
			t.Errorf("%s is %s, want trap_id %d", camelKind(s.Kind), o, s.TrapID)
		}
		seen[d.oid[len(d.oid)-1]] = s.Kind
	}
	for name, d := range defs {
		if d.kind == "NOTIFICATION-TYPE" && seen[d.oid[len(d.oid)-1]] == "" {
			t.Errorf("the MIB has notification %s that no event sends", name)
		}
	}
}

// fullSnapshot has every series the agent reads, for two providers.
func fullSnapshot() plugin.MetricsRecord {
	m := snapshot(t0, 1000)
	for _, p := range []string{"transit-a", "transit-b"} {
		for _, n := range []string{"packeteer_probe_loss_ratio", "packeteer_probe_rtt_seconds", "packeteer_probe_jitter_seconds"} {
			m.Samples = append(m.Samples, g(n, 0.01, "provider", p, "prefix", "203.0.113.0/24"))
		}
		m.Samples = append(m.Samples, g("packeteer_telemetry_up", 1, "provider", p, "interface", "ether0"))
		for _, n := range []string{"packeteer_telemetry_in_bps", "packeteer_telemetry_out_bps", "packeteer_telemetry_in_95th_bps",
			"packeteer_telemetry_out_95th_bps", "packeteer_telemetry_usage_bps", "packeteer_telemetry_commit_bps"} {
			m.Samples = append(m.Samples, g(n, 1e9, "provider", p, "interface", "ether0"))
		}
	}
	return m
}

func TestMIBHasNoStaleOrDuplicateNumbers(t *testing.T) {
	defs := parseMIB(t)
	byOID := map[string]string{}
	for name, d := range defs {
		o := oidString(d.oid)
		if other, dup := byOID[o]; dup {
			t.Errorf("%s and %s are both %s", name, other, o)
		}
		byOID[o] = name
		if len(name) > 64 {
			t.Errorf("%s is longer than the 64 characters SMIv2 allows", name)
		}
	}
	raw, _ := os.ReadFile("../../../../deploy/mib/PACKETEER-MIB.txt")
	for i, b := range raw {
		if b > 0x7e || (b < 0x20 && b != '\n') {
			t.Fatalf("the MIB has a non-ASCII or control byte at offset %d", i)
		}
	}
}
