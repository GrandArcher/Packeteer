package configedit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/linkout"
)

// Forms of #687: herd Atlas and the other outside sources, the herd
// resource limits, and link-outs. observeBlocksYAML carries limits and Atlas
// in the file already.

func limitFields(t *testing.T) []Field {
	t.Helper()
	b, _ := blockByID("herd")
	var out []Field
	for _, f := range b.Fields {
		if strings.HasPrefix(f.Key, "limits.") {
			out = append(out, f)
		}
	}
	return out
}

// The limit fields are the loader's: one per key, with its default and range,
// and none without text.
func TestHerdLimitFieldsMatchTheLoader(t *testing.T) {
	fields := limitFields(t)
	specs := config.HerdLimitSpecs()
	if len(fields) != len(specs) {
		t.Fatalf("%d fields for %d limits", len(fields), len(specs))
	}
	for i, s := range specs {
		f := fields[i]
		if f.Key != "limits."+s.Key || f.Label == "" || f.Help == "" || !f.Advanced || f.Min == nil || f.Max == nil {
			t.Errorf("%s: field = %+v", s.Key, f)
		}
		if s.Duration {
			if f.Kind != KindDuration || *f.Min != time.Duration(s.Min).Seconds() || *f.Max != time.Duration(s.Max).Seconds() {
				t.Errorf("%s: duration field = %+v", s.Key, f)
			}
			if d, err := time.ParseDuration(f.Default); err != nil || int64(d) != s.Default {
				t.Errorf("%s: default %q is not %d ns", s.Key, f.Default, s.Default)
			}
			continue
		}
		if f.Kind != KindInt || *f.Min != float64(s.Min) || *f.Max != float64(s.Max) || f.Default != strconv.FormatInt(s.Default, 10) {
			t.Errorf("%s: int field = %+v", s.Key, f)
		}
	}
	for key := range herdLimitText {
		if !slices.ContainsFunc(specs, func(s config.HerdLimitSpec) bool { return s.Key == key }) {
			t.Errorf("text for %s, which is not a limit", key)
		}
	}
}

func TestHerdOutsideAndLimitsReadTheFile(t *testing.T) {
	h := mustParse(t, observeBlocksYAML).Blocks["herd"]
	if h["outside.atlas.enabled"] != true || !reflect.DeepEqual(h["outside.atlas.measurements"], []string{"1001"}) ||
		len(h["outside.atlas.probes"].([]string)) != 0 || h["outside.atlas.refresh"] != "" || h["outside.ris"] != false || h["limits.rate_global"] != "700" || h["limits.queue"] != "" {
		t.Fatalf("herd = %+v", h)
	}
}

func TestHerdOutsideAndLimitsWrite(t *testing.T) {
	out, cfg := observeEdit(t, observeBlocksYAML, func(f *Form) {
		h := f.Blocks["herd"]
		h["outside.atlas.measurements"] = []string{"1001", "1002"}
		h["outside.atlas.probes"] = []string{"6001"}
		h["outside.atlas.refresh"] = "30m"
		h["outside.rpki"] = true
		h["outside.links"] = true
		h["limits.rate_global"] = "900"
		h["limits.pull_interval"] = "10m"
		h["limits.local_bytes"] = "1073741824"
	})
	o, l := cfg.Herd.Outside, cfg.Herd.Limits
	if !o.Atlas.Enabled || !reflect.DeepEqual(o.Atlas.Measurements, []int{1001, 1002}) || !reflect.DeepEqual(o.Atlas.Probes, []int{6001}) ||
		o.Atlas.Refresh != 30*time.Minute || !o.RPKI || !o.Links || o.RIS {
		t.Fatalf("outside = %+v\n%s", o, out)
	}
	if l.RateGlobal != 900 || l.PullInterval != 10*time.Minute || l.LocalBytes != 1073741824 || l.RatePerIdentity != 60 {
		t.Fatalf("limits = %+v\n%s", l, out)
	}
	// A key the operator did not touch keeps the file's text.
	if !strings.Contains(out, "# lab edge") || !strings.Contains(out, "listen: 0.0.0.0:9444") {
		t.Fatalf("the rest of the file changed:\n%s", out)
	}
}

// Atlas off and every limit empty write nothing: the keys leave the file, so
// the loader's defaults (Atlas off, the caps) apply.
func TestHerdOutsideAndLimitsDefaultsWriteNothing(t *testing.T) {
	out, cfg := observeEdit(t, observeBlocksYAML, func(f *Form) {
		h := f.Blocks["herd"]
		h["outside.atlas.enabled"] = false
		h["outside.atlas.measurements"] = []string{}
		h["limits.rate_global"] = ""
	})
	if strings.Contains(out, "limits") || strings.Contains(out, "outside") || strings.Contains(out, "atlas") {
		t.Fatalf("defaults were written:\n%s", out)
	}
	o := cfg.Herd.Outside
	if o.Atlas.Enabled || o.RIS || o.RPKI || o.Links || cfg.Herd.Limits.RateGlobal != 600 {
		t.Fatalf("defaults = %+v, %+v", o, cfg.Herd.Limits)
	}
}

// No outside source starts on and every limit has a cap, so a form that is
// switched on and left alone reads nothing from outside and bounds the node.
func TestHerdOutsideAndLimitsDefaultsAreOffOrCaps(t *testing.T) {
	b, _ := blockByID("herd")
	for _, f := range b.Fields {
		if !strings.HasPrefix(f.Key, "outside.") {
			continue
		}
		if f.DefaultTrue || f.StartOn {
			t.Errorf("%s starts on", f.Key)
		}
	}
	for _, f := range limitFields(t) {
		if f.Max == nil || f.Default == "" || f.Required {
			t.Errorf("%s has no cap or default: %+v", f.Key, f)
		}
	}
}

func TestHerdOutsideAndLimitsRefusals(t *testing.T) {
	cases := []struct {
		name string
		edit func(v Values)
		want string
	}{
		{"atlas without ids", func(v Values) { v["outside.atlas.measurements"] = []string{} }, "herd.outside.atlas.measurements: name at least one"},
		{"atlas ids while off", func(v Values) { v["outside.atlas.enabled"] = false }, "herd.outside.atlas.enabled: turn Atlas on"},
		{"atlas refresh while off", func(v Values) {
			v["outside.atlas.enabled"], v["outside.atlas.measurements"], v["outside.atlas.refresh"] = false, []string{}, "20m"
		}, "herd.outside.atlas.enabled: turn Atlas on"},
		{"atlas id zero", func(v Values) { v["outside.atlas.measurements"] = []string{"0"} }, "outside.atlas.measurements[0]"},
		{"atlas id text", func(v Values) { v["outside.atlas.probes"] = []string{"abc"} }, "whole number"},
		{"atlas too many", func(v Values) { v["outside.atlas.measurements"] = []string{"1", "2", "3", "4", "5"} }, "herd.outside.atlas.measurements: at most 4"},
		{"atlas refresh low", func(v Values) { v["outside.atlas.refresh"] = "14m" }, "outside.atlas.refresh"},
		{"atlas refresh high", func(v Values) { v["outside.atlas.refresh"] = "25h" }, "outside.atlas.refresh"},
		{"limit below range", func(v Values) { v["limits.max_request_bytes"] = "100" }, "limits.max_request_bytes"},
		{"limit above range", func(v Values) { v["limits.rate_global"] = "1000001" }, "limits.rate_global"},
		{"limit text", func(v Values) { v["limits.queue"] = "many" }, "whole number"},
		{"limit duration", func(v Values) { v["limits.timeout"] = "10m" }, "limits.timeout"},
		{"limit duration text", func(v Values) { v["limits.pull_timeout"] = "fast" }, "duration"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := mustParse(t, observeBlocksYAML)
			c.edit(f.Blocks["herd"])
			_, err := ApplyForm([]byte(observeBlocksYAML), roundTripJSON(t, f))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

// The outside switches that name another block are the loader's to refuse:
// the merged text does not load, with the loader's message.
func TestHerdOutsideNeedsItsBlocks(t *testing.T) {
	f := mustParse(t, observeBlocksYAML)
	f.Blocks["herd"]["outside.ris"] = true
	out, err := ApplyForm([]byte(observeBlocksYAML), roundTripJSON(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.Parse(out); err == nil || !strings.Contains(err.Error(), "herd.outside.ris needs leak_watch") {
		t.Fatalf("err = %v", err)
	}
	g := mustParse(t, observeBlocksYAML)
	g.Blocks["rpki"] = nil
	g.Blocks["rpki_only_invalid"] = nil
	g.Blocks["herd"]["outside.rpki"] = true
	out, err = ApplyForm([]byte(observeBlocksYAML), roundTripJSON(t, g))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.Parse(out); err == nil || !strings.Contains(err.Error(), "herd.outside.rpki needs rpki enabled") {
		t.Fatalf("err = %v", err)
	}
}

const linkoutsYAML = `mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
allowlist:
  prefixes: [198.51.100.0/24]
`

func TestLinkoutsFormReadsDefaultsAndWritesNothing(t *testing.T) {
	f := mustParse(t, linkoutsYAML)
	v := f.Blocks["linkouts"]
	if v == nil || !reflect.DeepEqual(v["enabled"], linkout.DefaultSites()) || v["hide_internal"] != true || len(v["custom"].([]Values)) != 0 {
		t.Fatalf("linkouts = %+v", v)
	}
	for _, form := range []Form{f, roundTripJSON(t, f)} {
		out, err := ApplyForm([]byte(linkoutsYAML), form)
		if err != nil || string(out) != linkoutsYAML {
			t.Fatalf("unchanged form changed the file: %v\n%s", err, out)
		}
	}
}

func TestLinkoutsFormWrites(t *testing.T) {
	out, cfg := observeEdit(t, linkoutsYAML, func(f *Form) {
		v := f.Blocks["linkouts"]
		v["enabled"] = []string{"he", "ripestat", "nlnog_ring"}
		v["custom"] = []Values{{"name": "internal LG", "url": "https://lg.example.net/route?prefix={prefix}"}}
		v["hide_internal"] = false
	})
	l := cfg.Linkouts
	if !reflect.DeepEqual(l.Enabled, []string{"he", "ripestat", "nlnog_ring"}) || len(l.Custom) != 1 || l.Custom[0].Name != "internal LG" ||
		l.HideInternal == nil || *l.HideInternal {
		t.Fatalf("linkouts = %+v\n%s", l, out)
	}
	// Back to the defaults: hide_internal leaves the file, the rest stays as written.
	out2, cfg2 := observeEdit(t, out, func(f *Form) {
		f.Blocks["linkouts"]["hide_internal"] = true
		f.Blocks["linkouts"]["custom"] = []Values{}
	})
	if strings.Contains(out2, "hide_internal") || strings.Contains(out2, "custom") || cfg2.Linkouts.HideInternal != nil || len(cfg2.Linkouts.Custom) != 0 {
		t.Fatalf("defaults were written:\n%s", out2)
	}
}

// Not set shows the default sites, and an emptied list is written as an
// empty list, which shows no built-in site; it never falls back to the
// defaults.
func TestLinkoutsEmptiedListShowsNoSite(t *testing.T) {
	out, cfg := observeEdit(t, linkoutsYAML, func(f *Form) { f.Blocks["linkouts"]["enabled"] = []string{} })
	if cfg.Linkouts.Enabled == nil || len(cfg.Linkouts.Enabled) != 0 || !strings.Contains(out, "enabled: []") {
		t.Fatalf("enabled = %#v\n%s", cfg.Linkouts.Enabled, out)
	}
	if got := linkout.New(cfg.Linkouts).ASN(64496); len(got) != 0 {
		t.Fatalf("links = %v", got)
	}
	back := mustParse(t, out).Blocks["linkouts"]
	if len(back["enabled"].([]string)) != 0 {
		t.Fatalf("an explicit empty list reads as %v", back["enabled"])
	}
	// Filling it again replaces the empty list in place.
	_, cfg2 := observeEdit(t, out, func(f *Form) { f.Blocks["linkouts"]["enabled"] = []string{"he"} })
	if !reflect.DeepEqual(cfg2.Linkouts.Enabled, []string{"he"}) {
		t.Fatalf("enabled = %v", cfg2.Linkouts.Enabled)
	}
}

func TestLinkoutsRefusals(t *testing.T) {
	many := make([]Values, 21)
	for i := range many {
		many[i] = Values{"name": "site" + strconv.Itoa(i), "url": "https://lg.example.net/{asn}"}
	}
	cases := []struct {
		name string
		edit func(v Values)
		want string
	}{
		{"unknown site", func(v Values) { v["enabled"] = []string{"he", "altavista"} }, "linkouts.enabled[1]"},
		{"site twice", func(v Values) { v["enabled"] = []string{"he", "he"} }, "duplicate value he"},
		{"http url", func(v Values) {
			v["custom"] = []Values{{"name": "lg", "url": "http://lg.example.net/{asn}"}}
		}, "https"},
		{"no placeholder", func(v Values) {
			v["custom"] = []Values{{"name": "lg", "url": "https://lg.example.net/"}}
		}, "{prefix} or {asn}"},
		{"both placeholders", func(v Values) {
			v["custom"] = []Values{{"name": "lg", "url": "https://lg.example.net/{asn}/{prefix}"}}
		}, "not both"},
		{"placeholder in host", func(v Values) {
			v["custom"] = []Values{{"name": "lg", "url": "https://{asn}.example.net/"}}
		}, "host"},
		{"login", func(v Values) {
			v["custom"] = []Values{{"name": "lg", "url": "https://user:pw@lg.example.net/{asn}"}}
		}, "credentials"},
		{"long name", func(v Values) {
			v["custom"] = []Values{{"name": strings.Repeat("n", 41), "url": "https://lg.example.net/{asn}"}}
		}, "linkouts.custom[0].name"},
		{"no name", func(v Values) { v["custom"] = []Values{{"name": "", "url": "https://lg.example.net/{asn}"}} }, "linkouts.custom[0].name: is required"},
		{"name twice", func(v Values) {
			v["custom"] = []Values{{"name": "lg", "url": "https://lg.example.net/{asn}"}, {"name": "lg", "url": "https://lg2.example.net/{asn}"}}
		}, "duplicate lg"},
		{"too many", func(v Values) { v["custom"] = many }, "at most 20"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := mustParse(t, linkoutsYAML)
			c.edit(f.Blocks["linkouts"])
			_, err := ApplyForm([]byte(linkoutsYAML), roundTripJSON(t, f))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

// A null site list is not set to the loader, so the form shows the defaults.
func TestLinkoutsNullListReadsAsDefaults(t *testing.T) {
	got := mustParse(t, linkoutsYAML+"linkouts:\n  enabled:\n").Blocks["linkouts"]["enabled"]
	if !reflect.DeepEqual(got, linkout.DefaultSites()) {
		t.Fatalf("enabled = %v", got)
	}
}

// Forms of #694: herd.block and herd.down_weight. They change this node's
// view only and are never read by Decide.

const herdKeyID = "abababababababababababababababababababababababababababababababab"

func TestHerdViewFieldsReadTheFile(t *testing.T) {
	h := mustParse(t, observeBlocksYAML).Blocks["herd"]
	if !reflect.DeepEqual(h["block.asns"], []string{"64502"}) || len(h["block.keys"].([]string)) != 0 || len(h["down_weight.asns"].([]string)) != 0 {
		t.Fatalf("herd = %+v", h)
	}
	b, _ := blockByID("herd")
	for _, f := range b.Fields {
		if (strings.HasPrefix(f.Key, "block.") || strings.HasPrefix(f.Key, "down_weight.")) && (f.Required || f.StartOn || f.DefaultTrue || f.Default != "" || !f.Advanced) {
			t.Errorf("%s must be an optional advanced list that starts empty: %+v", f.Key, f)
		}
	}
}

func TestHerdViewFieldsWrite(t *testing.T) {
	out, cfg := observeEdit(t, observeBlocksYAML, func(f *Form) {
		h := f.Blocks["herd"]
		h["block.asns"] = []string{"64502", "64503"}
		h["block.keys"] = []string{herdKeyID}
		h["down_weight.asns"] = []string{"64504"}
		h["down_weight.endpoints"] = []string{"https://198.51.100.7:9444"}
	})
	b, d := cfg.Herd.Block, cfg.Herd.DownWeight
	if !reflect.DeepEqual(b.ASNs, []uint32{64502, 64503}) || !reflect.DeepEqual(b.Keys, []string{herdKeyID}) || len(b.Endpoints) != 0 ||
		!reflect.DeepEqual(d.ASNs, []uint32{64504}) || !reflect.DeepEqual(d.Endpoints, []string{"https://198.51.100.7:9444"}) || len(d.Keys) != 0 {
		t.Fatalf("block = %+v down_weight = %+v\n%s", b, d, out)
	}
	if !strings.Contains(out, "# lab edge") || !strings.Contains(out, "limits: {rate_global: 700}") {
		t.Fatalf("the rest of the file changed:\n%s", out)
	}
}

// Emptying the lists removes the keys: nothing is blocked or down-weighted by
// default.
func TestHerdViewFieldsEmptyWriteNothing(t *testing.T) {
	out, cfg := observeEdit(t, observeBlocksYAML, func(f *Form) { f.Blocks["herd"]["block.asns"] = []string{} })
	if strings.Contains(out, "block") || strings.Contains(out, "down_weight") || len(cfg.Herd.Block.ASNs) != 0 || len(cfg.Herd.DownWeight.ASNs) != 0 {
		t.Fatalf("an empty view was written:\n%s", out)
	}
}

func TestHerdViewFieldsRefusals(t *testing.T) {
	many := make([]string, 256)
	for i := range many {
		many[i] = strconv.Itoa(1 + i)
	}
	cases := []struct {
		name string
		edit func(v Values)
		want string
	}{
		{"asn zero", func(v Values) { v["block.asns"] = []string{"0"} }, "block.asns[0]"},
		{"asn text", func(v Values) { v["down_weight.asns"] = []string{"AS64504"} }, "whole number"},
		{"key id short", func(v Values) { v["block.keys"] = []string{"abc"} }, "herd.block.keys[0]: \"abc\" must be a key id"},
		{"key id upper case", func(v Values) { v["down_weight.keys"] = []string{strings.ToUpper(herdKeyID)} }, "herd.down_weight.keys[0]"},
		{"endpoint http", func(v Values) { v["block.endpoints"] = []string{"http://198.51.100.7:9444"} }, "herd.block.endpoints[0]"},
		{"endpoint without port", func(v Values) { v["down_weight.endpoints"] = []string{"https://198.51.100.7"} }, "needs a port"},
		{"asn twice", func(v Values) { v["block.asns"] = []string{"64502", "64502"} }, "duplicate value 64502"},
		{"member in both", func(v Values) { v["down_weight.asns"] = []string{"64502"} }, "herd.down_weight.asns[0]: already listed in herd.block"},
		{"key in both", func(v Values) {
			v["block.keys"], v["down_weight.keys"] = []string{herdKeyID}, []string{herdKeyID}
		}, "herd.down_weight.keys[0]: already listed in herd.block"},
		{"too many", func(v Values) { v["block.asns"], v["block.keys"] = many, []string{herdKeyID} }, "herd.block.asns: at most 256 entries"},
		{"preview only", func(v Values) { v["preview_only"] = true }, "herd.block.asns: preview_only serves and pulls nothing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := mustParse(t, observeBlocksYAML)
			c.edit(f.Blocks["herd"])
			_, err := ApplyForm([]byte(observeBlocksYAML), roundTripJSON(t, f))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

// A block or down-weight edit leaves mode, the allowlist, the announcer, and
// the route community as they were, and nothing in the decision path or the
// announcers names the herd config.
func TestHerdViewEditNeverReachesDecideOrTheAnnouncer(t *testing.T) {
	out, cfg := observeEdit(t, observeBlocksYAML, func(f *Form) {
		f.Blocks["herd"]["block.keys"] = []string{herdKeyID}
		f.Blocks["herd"]["down_weight.asns"] = []string{"64504"}
	})
	if cfg.Mode != "observe" || cfg.Announcer == nil || cfg.Announcer.Type != "gobgp" || cfg.PacketeerCommunity != "64512:666" ||
		len(cfg.Allowlist.Prefixes) != 1 || cfg.Allowlist.Prefixes[0] != "198.51.100.0/24" {
		t.Fatalf("safety keys changed:\n%s", out)
	}
	fset := token.NewFileSet()
	for _, dir := range []string{"../policy", "../plugins/announcer"} {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Herd" || sel.Sel.Name == "DownWeight") {
					t.Errorf("%s reads %s", fset.Position(sel.Pos()), sel.Sel.Name)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
