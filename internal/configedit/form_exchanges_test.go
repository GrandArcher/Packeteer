package configedit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// exchangeFormYAML is an edge with one transit, an exchange of two peers
// (peer-b has a precedence and exclude), and the add-path
// session the route check needs. Documentation addresses and ASNs only.
const exchangeFormYAML = `# edge
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.21
exchanges:
  - name: ix-lab
    lans: [203.0.113.0/24]
    group: ix
    peers:
      - name: ix-peer-a
        asn: 64501
        next_hop: 203.0.113.11
        source_ip: 192.0.2.31
      - name: ix-peer-b # keep me
        asn: 64502
        next_hop: 203.0.113.12
        source_ip: 192.0.2.32
        precedence: 50
        exclude: true
bgp:
  neighbors:
    - address: 192.0.2.254
      add_path: true
`

func peerByName(t *testing.T, cfg *config.Config, name string) config.Provider {
	t.Helper()
	for _, p := range cfg.Providers {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("no provider %s", name)
	return config.Provider{}
}

func TestFormExchangesParse(t *testing.T) {
	f, err := ParseForm([]byte(exchangeFormYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Exchanges) != 1 {
		t.Fatalf("exchanges = %+v", f.Exchanges)
	}
	ex := f.Exchanges[0]
	if ex.Key != "ix-lab" || ex.Name != "ix-lab" || ex.Group != "ix" || ex.BMP != "" ||
		len(ex.LANs) != 1 || ex.LANs[0] != "203.0.113.0/24" || len(ex.Peers) != 2 {
		t.Fatalf("exchange = %+v", ex)
	}
	if want := (FormExchangePeer{Key: "ix-peer-b", Name: "ix-peer-b", ASN: "64502", NextHop: "203.0.113.12", SourceIP: "192.0.2.32", Exclude: true, Precedence: "50"}); ex.Peers[1] != want {
		t.Fatalf("peer = %+v, want %+v", ex.Peers[1], want)
	}
	if len(f.Providers) != 1 {
		t.Fatalf("exchange peers leaked into providers: %+v", f.Providers)
	}
	none, err := ParseForm([]byte(observeYAML))
	if err != nil || none.Exchanges == nil || len(none.Exchanges) != 0 {
		t.Fatalf("file without exchanges: %+v %v", none.Exchanges, err)
	}
}

// An untouched form returns the file byte for byte, comments included.
func TestFormExchangesUnchangedKeepsBytes(t *testing.T) {
	f, err := ParseForm([]byte(exchangeFormYAML))
	if err != nil {
		t.Fatal(err)
	}
	out, err := ApplyForm([]byte(exchangeFormYAML), f)
	if err != nil || string(out) != exchangeFormYAML {
		t.Fatalf("unchanged form changed the file: %v\n%s", err, out)
	}
}

func TestFormExchangesEditRoundTrip(t *testing.T) {
	out, cfg := applyAndLoad(t, exchangeFormYAML, func(f *Form) {
		ex := &f.Exchanges[0]
		ex.LANs = append(ex.LANs, "2001:db8:1::/64")
		ex.Peers[0].ASN = "64511"
		ex.Peers[0].Cost = "1.5"
		ex.Peers = append(ex.Peers, FormExchangePeer{Name: "ix-peer-c", ASN: "64503", NextHop: "2001:db8:1::13", SourceIP: "2001:db8::33"})
	})
	a := peerByName(t, cfg, "ix-peer-a")
	if a.Exchange != "ix-lab" || a.PeerASN != 64511 || a.Cost == nil || *a.Cost != 1.5 || a.Group != "ix" || !a.AddPath {
		t.Fatalf("peer a = %+v", a)
	}
	c := peerByName(t, cfg, "ix-peer-c")
	if c.PeerASN != 64503 || c.NextHop != "2001:db8:1::13" || c.Exchange != "ix-lab" {
		t.Fatalf("peer c = %+v", c)
	}
	b := peerByName(t, cfg, "ix-peer-b")
	if b.Precedence != 50 || !b.Exclude {
		t.Fatalf("hidden keys were lost: %+v\n%s", b, out)
	}
	if !strings.Contains(out, "# edge") || !strings.Contains(out, "# keep me") {
		t.Fatalf("comments lost:\n%s", out)
	}
	if len(cfg.Providers) != 4 {
		t.Fatalf("providers = %d", len(cfg.Providers))
	}
}

// TestFormExchangesPeerExcludeAndPrecedence (#330): a peer's exclude and
// precedence are form fields. Editing one writes only that peer's keys, and
// clearing them removes the keys.
func TestFormExchangesPeerExcludeAndPrecedence(t *testing.T) {
	out, cfg := applyAndLoad(t, exchangeFormYAML, func(f *Form) {
		f.Exchanges[0].Peers[0].Exclude = true
		f.Exchanges[0].Peers[0].Precedence = "20"
		f.Exchanges[0].Peers[1].Exclude = false
		f.Exchanges[0].Peers[1].Precedence = ""
	})
	a, b := peerByName(t, cfg, "ix-peer-a"), peerByName(t, cfg, "ix-peer-b")
	if !a.Exclude || a.Precedence != 20 || b.Exclude || b.Precedence != 0 {
		t.Fatalf("a = %+v b = %+v\n%s", a, b, out)
	}
	if strings.Contains(out, "precedence: 50") || !strings.Contains(out, "# keep me") {
		t.Fatalf("cleared keys stayed or comments lost:\n%s", out)
	}
	f, err := ParseForm([]byte(exchangeFormYAML))
	if err != nil {
		t.Fatal(err)
	}
	f.Exchanges[0].Peers[0].Precedence = "high"
	if _, err := ApplyForm([]byte(exchangeFormYAML), f); err == nil || !strings.Contains(err.Error(), "precedence") {
		t.Fatalf("a bad precedence was accepted: %v", err)
	}
}

func TestFormExchangesAdd(t *testing.T) {
	// bmp: prefer needs a rib_sources entry, which the form leaves alone.
	withBMP := exchangeFormYAML + "rib_sources:\n  - type: bmp\n    config:\n      routers: [192.0.2.254]\n"
	_, cfg := applyAndLoad(t, withBMP, func(f *Form) {
		f.Exchanges = append(f.Exchanges, FormExchange{
			Name: "ix-two", LANs: []string{"198.51.100.0/24"}, BMP: "prefer",
			Peers: []FormExchangePeer{{Name: "two-a", ASN: "64504", NextHop: "198.51.100.4", SourceIP: "192.0.2.41", Cost: "2"}},
		})
	})
	two := peerByName(t, cfg, "two-a")
	if two.Exchange != "ix-two" || two.BMP != "prefer" || two.PeerASN != 64504 {
		t.Fatalf("two-a = %+v", two)
	}
}

func TestFormExchangesRemoveAll(t *testing.T) {
	out, cfg := applyAndLoad(t, exchangeFormYAML, func(f *Form) { f.Exchanges = []FormExchange{} })
	if strings.Contains(out, "exchanges:") || len(cfg.Exchanges) != 0 || len(cfg.Providers) != 1 {
		t.Fatalf("exchanges not removed:\n%s", out)
	}
}

// A file whose only providers are exchange peers is valid, and the form
// does not ask for a top-level provider.
func TestFormExchangesOnlyPeers(t *testing.T) {
	_, cfg := applyAndLoad(t, exchangeFormYAML, func(f *Form) { f.Providers = []FormProvider{} })
	if len(cfg.Providers) != 2 || cfg.Providers[0].Exchange != "ix-lab" {
		t.Fatalf("providers = %+v", cfg.Providers)
	}
	f, _ := ParseForm([]byte(observeYAML))
	f.Providers = nil
	if _, err := ApplyForm([]byte(observeYAML), f); err == nil || !strings.Contains(err.Error(), "at least one provider") {
		t.Fatalf("no providers and no peers: err = %v", err)
	}
}

func TestFormExchangesOmittedIsUntouched(t *testing.T) {
	f, err := ParseForm([]byte(exchangeFormYAML))
	if err != nil {
		t.Fatal(err)
	}
	f.Exchanges = nil
	f.HoldTime = "20m"
	out, err := ApplyForm([]byte(exchangeFormYAML), f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "hold_time: 20m") || !strings.Contains(string(out), "name: ix-peer-b") {
		t.Fatalf("omitted exchanges changed:\n%s", out)
	}
}

// The form edits YAML text only. The loader's route check requirement
// (add_path or bmp) is Save's check, so a file without it applies and then
// fails to load with the loader's own message.
func TestFormExchangesRouteCheckIsTheLoaders(t *testing.T) {
	noPaths := strings.Replace(exchangeFormYAML, "      add_path: true\n", "", 1)
	f, err := ParseForm([]byte(noPaths))
	if err != nil {
		t.Fatal(err)
	}
	f.Exchanges[0].Peers[0].ASN = "64511"
	out, err := ApplyForm([]byte(noPaths), f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.Parse(out); err == nil || !strings.Contains(err.Error(), "peers need their paths visible") {
		t.Fatalf("loader err = %v", err)
	}
}

func TestFormExchangesErrors(t *testing.T) {
	good := FormExchangePeer{Name: "p", ASN: "64501", NextHop: "203.0.113.20", SourceIP: "192.0.2.50"}
	for name, tc := range map[string]struct {
		edit func(*Form)
		want string
	}{
		"no name":       {func(f *Form) { f.Exchanges[0].Name = "" }, "name"},
		"bad name":      {func(f *Form) { f.Exchanges[0].Name = "ix lab" }, "must be 1 to 64"},
		"provider name": {func(f *Form) { f.Exchanges[0].Name = "transit-a" }, "already used by a provider"},
		"duplicate exchange": {func(f *Form) {
			f.Exchanges = append(f.Exchanges, FormExchange{Name: "ix-lab", LANs: []string{"198.51.100.0/24"}, Peers: []FormExchangePeer{good}})
		}, "already used by an exchange"},
		"no lans":          {func(f *Form) { f.Exchanges[0].LANs = nil }, "at least one peering LAN"},
		"host bits":        {func(f *Form) { f.Exchanges[0].LANs = []string{"203.0.113.1/24"} }, "without host bits"},
		"bad bmp":          {func(f *Form) { f.Exchanges[0].BMP = "all" }, "bmp"},
		"bad group":        {func(f *Form) { f.Exchanges[0].Group = "a b" }, "group"},
		"no peers":         {func(f *Form) { f.Exchanges[0].Peers = nil }, "at least one peer"},
		"peer no name":     {func(f *Form) { f.Exchanges[0].Peers[0].Name = "" }, "name is required"},
		"peer is provider": {func(f *Form) { f.Exchanges[0].Peers[0].Name = "transit-a" }, "already used by a provider"},
		"peer twice":       {func(f *Form) { f.Exchanges[0].Peers[0].Name = "ix-peer-b" }, "already used by a peer"},
		"peer is exchange": {func(f *Form) { f.Exchanges[0].Peers[0].Name = "ix-lab" }, "already used by an exchange"},
		"no asn":           {func(f *Form) { f.Exchanges[0].Peers[0].ASN = "" }, "asn"},
		"zero asn":         {func(f *Form) { f.Exchanges[0].Peers[0].ASN = "0" }, "asn"},
		"big asn":          {func(f *Form) { f.Exchanges[0].Peers[0].ASN = "4294967296" }, "asn"},
		"bad next hop":     {func(f *Form) { f.Exchanges[0].Peers[0].NextHop = "peer" }, "not an IP"},
		"hop off lan":      {func(f *Form) { f.Exchanges[0].Peers[0].NextHop = "198.51.100.9" }, "not inside the exchange's LANs"},
		"bad source":       {func(f *Form) { f.Exchanges[0].Peers[0].SourceIP = "x" }, "source_ip"},
		"neg cost":         {func(f *Form) { f.Exchanges[0].Peers[0].Cost = "-1" }, "cost"},
		"row twice":        {func(f *Form) { f.Exchanges[0].Peers[0].Key = "ix-peer-b"; f.Exchanges[0].Peers[1].Key = "ix-peer-b" }, "listed twice"},
		"stale key":        {func(f *Form) { f.Exchanges[0].Key = "gone" }, "not in the file anymore"},
	} {
		f, err := ParseForm([]byte(exchangeFormYAML))
		if err != nil {
			t.Fatal(err)
		}
		tc.edit(&f)
		_, err = ApplyForm([]byte(exchangeFormYAML), f)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

// #155: a draft peer from a discovered member carries only the AS and next
// hop. Once named and given a probe source it is written like any peer;
// the draft flag is never written, and without the name or source the
// start checks refuse it.
func TestFormExchangesDraftPeer(t *testing.T) {
	draft := FormExchangePeer{ASN: "64503", NextHop: "203.0.113.13", Draft: true}

	f, err := ParseForm([]byte(exchangeFormYAML))
	if err != nil {
		t.Fatal(err)
	}
	f.Exchanges[0].Peers = append(f.Exchanges[0].Peers, draft)
	if _, err := ApplyForm([]byte(exchangeFormYAML), f); err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("unnamed draft: err = %v", err)
	}

	f.Exchanges[0].Peers[2].Name = "ix-peer-c"
	out, err := ApplyForm([]byte(exchangeFormYAML), f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "draft") {
		t.Fatalf("draft flag was written:\n%s", out)
	}
	if _, err := config.Parse(out); err == nil || !strings.Contains(err.Error(), "source_ip") {
		t.Fatalf("a draft without a probe source must not load: err = %v", err)
	}

	f.Exchanges[0].Peers[2].SourceIP = "192.0.2.33"
	out, err = ApplyForm([]byte(exchangeFormYAML), f)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, out)
	}
	c := peerByName(t, cfg, "ix-peer-c")
	if c.PeerASN != 64503 || c.NextHop != "203.0.113.13" || c.Exchange != "ix-lab" || c.Cost != nil {
		t.Fatalf("peer c = %+v", c)
	}
	if cfg.Mode != config.ModeObserve {
		t.Fatalf("mode = %q", cfg.Mode)
	}
}

// The form has no field for exchanges[].health (#149); a form edit keeps it.
func TestFormExchangesKeepHealth(t *testing.T) {
	src := strings.Replace(exchangeFormYAML, "    group: ix\n", "    group: ix\n    health: {loss_pct: 30, min_peers: 2, window: 10m}\n", 1)
	_, cfg := applyAndLoad(t, src, func(f *Form) { f.Exchanges[0].Peers[0].ASN = "64511" })
	h := cfg.Exchanges[0].Health
	if h.LossPct != 30 || h.MinPeers != 2 || h.Window != 10*time.Minute {
		t.Fatalf("health = %+v", h)
	}
}

// The form has no field for exchanges[].port (#151); a form edit keeps it.
func TestFormExchangesKeepPort(t *testing.T) {
	src := strings.Replace(exchangeFormYAML, "    group: ix\n", "    group: ix\n    port: {capacity_mbps: 10000, commit_mbps: 6000, port_cost: 1500}\n", 1)
	_, cfg := applyAndLoad(t, src, func(f *Form) { f.Exchanges[0].Peers[0].ASN = "64511" })
	pt := cfg.Exchanges[0].Port
	if pt == nil || pt.CapacityMbps != 10000 || pt.CommitMbps != 6000 || pt.PortCost == nil || *pt.PortCost != 1500 {
		t.Fatalf("port = %+v", pt)
	}
}

// TestFormOmittedFieldsKeepFile (#330): a client older than the provider bmp
// and peer exclude and precedence fields posts rows without them. The file's
// values stay; the edit it did send is written.
func TestFormOmittedFieldsKeepFile(t *testing.T) {
	in := strings.Replace(exchangeFormYAML, "next_hop: 192.0.2.21\n", "next_hop: 192.0.2.21\n    bmp: prefer\n", 1) +
		"rib_sources:\n  - type: bmp\n    config:\n      routers: [192.0.2.254]\n"
	out, cfg := applyAndLoad(t, in, func(f *Form) {
		f.Providers[0].Cost = "5"
		f.Exchanges[0].Peers[1].Cost = "7"
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err := json.Unmarshal(b, &raw); err != nil {
			t.Fatal(err)
		}
		delete(raw["providers"].([]any)[0].(map[string]any), "bmp")
		for _, p := range raw["exchanges"].([]any)[0].(map[string]any)["peers"].([]any) {
			delete(p.(map[string]any), "exclude")
			delete(p.(map[string]any), "precedence")
		}
		if b, err = json.Marshal(raw); err != nil {
			t.Fatal(err)
		}
		*f = Form{}
		if err := json.Unmarshal(b, f); err != nil {
			t.Fatal(err)
		}
	})
	a, peer := peerByName(t, cfg, "transit-a"), peerByName(t, cfg, "ix-peer-b")
	if a.BMP != config.BMPPrefer || a.Cost == nil || *a.Cost != 5 {
		t.Fatalf("provider = %+v\n%s", a, out)
	}
	if peer.Precedence != 50 || !peer.Exclude || peer.Cost == nil || *peer.Cost != 7 {
		t.Fatalf("peer = %+v\n%s", peer, out)
	}

	// A client that sends the fields still clears them.
	_, cfg = applyAndLoad(t, in, func(f *Form) {
		f.Providers[0].BMP = ""
		f.Exchanges[0].Peers[1].Exclude = false
		f.Exchanges[0].Peers[1].Precedence = ""
		*f = roundTripJSON(t, *f)
	})
	a, peer = peerByName(t, cfg, "transit-a"), peerByName(t, cfg, "ix-peer-b")
	if (a.BMP != config.BMPOff && a.BMP != "") || peer.Exclude || peer.Precedence != 0 {
		t.Fatalf("sent fields not cleared: provider %+v peer %+v", a, peer)
	}
}
