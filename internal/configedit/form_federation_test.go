package configedit

import (
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// federationYAML is an observe-mode POP with a federation block, a pushed
// section pair, an allowlist, and keys the form does not know. Documentation
// addresses and ASNs only.
const federationYAML = `# pop-a, lab
mode: observe
asn: 64512
router_id: 192.0.2.10
domain: pop-a
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
allowlist:
  prefixes: [198.51.100.0/24]
policies:
  - type: rules
    config:
      rules:
        - name: keep-a
          providers: [transit-a]
federation:
  type: mtls
  config:
    listen: 0.0.0.0:9443
    cert_file: /etc/packeteer/certs/pop-a.crt
    key_file: /etc/packeteer/certs/pop-a.key
    ca_file: /etc/packeteer/certs/ca.crt
    poll_interval: 1s # lab
    peers:
      - name: pop-b
        url: https://192.0.2.20:9443
        future_key: kept
`

func fedEdit(t *testing.T, src string, edit func(f *Form)) (string, *config.Config) {
	t.Helper()
	f := mustParse(t, src)
	edit(&f)
	// The page sends JSON; so does this.
	out, err := ApplyForm([]byte(src), roundTripJSON(t, f))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("the merged text does not load: %v\n%s", err, out)
	}
	return string(out), cfg
}

func fedGroup(f *Form) Values { return f.Blocks["federation"]["federation"].(Values) }

func TestFederationBlockReadsTheFile(t *testing.T) {
	f := mustParse(t, federationYAML)
	b := f.Blocks["federation"]
	g := b["federation"].(Values)
	if b["domain"] != "pop-a" || g["type"] != "mtls" || g["config.listen"] != "0.0.0.0:9443" || g["config.poll_interval"] != "1s" {
		t.Fatalf("block = %+v", b)
	}
	peers := g["config.peers"].([]Values)
	if len(peers) != 1 || peers[0]["name"] != "pop-b" || peers[0]["url"] != "https://192.0.2.20:9443" {
		t.Fatalf("peers = %+v", peers)
	}
	if got := g["config.accept_settings_from"].([]string); len(got) != 0 {
		t.Fatalf("accept_settings_from = %v, want none (push is off by default)", got)
	}
	none := mustParse(t, observeYAML)
	if none.Blocks["federation"]["federation"].(Values) != nil {
		t.Fatalf("a file without federation reads as having it: %+v", none.Blocks["federation"])
	}
}

func TestFederationUnchangedFormWritesNothing(t *testing.T) {
	f := mustParse(t, federationYAML)
	for _, form := range []Form{f, roundTripJSON(t, f)} {
		out, err := ApplyForm([]byte(federationYAML), form)
		if err != nil || string(out) != federationYAML {
			t.Fatalf("unchanged form changed the file: %v\n%s", err, out)
		}
	}
}

func TestFederationEditPeersAndAcceptKeepsTheRest(t *testing.T) {
	out, cfg := fedEdit(t, federationYAML, func(f *Form) {
		g := fedGroup(f)
		peers := g["config.peers"].([]Values)
		peers[0]["server_name"] = "pop-b.lab.test"
		g["config.peers"] = append(peers, Values{"name": "pop-c", "url": "https://192.0.2.30:9443", "domain": "pop-c"})
		g["config.accept_settings_from"] = []string{"pop-b", "pop-c"}
		g["config.max_age"] = "10s"
	})
	var spec struct {
		Peers   []map[string]string `yaml:"peers"`
		Accept  []string            `yaml:"accept_settings_from"`
		MaxAge  string              `yaml:"max_age"`
		PollInt string              `yaml:"poll_interval"`
	}
	if err := cfg.Federation.Config.Decode(&spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Peers) != 2 || spec.Peers[0]["server_name"] != "pop-b.lab.test" || spec.Peers[0]["future_key"] != "kept" ||
		spec.Peers[1]["name"] != "pop-c" || spec.Peers[1]["domain"] != "pop-c" {
		t.Fatalf("peers = %+v\n%s", spec.Peers, out)
	}
	if len(spec.Accept) != 2 || spec.Accept[1] != "pop-c" || spec.MaxAge != "10s" || spec.PollInt != "1s" {
		t.Fatalf("spec = %+v", spec)
	}
	if !strings.Contains(out, "# pop-a, lab") || !strings.Contains(out, "poll_interval: 1s # lab") {
		t.Fatalf("comments lost:\n%s", out)
	}
}

// The form never reaches the keys a push is refused on: mode, the
// allowlist, the announcer, and the pushed sections stay byte for byte.
func TestFederationEditLeavesSafetyKeysAlone(t *testing.T) {
	out, cfg := fedEdit(t, federationYAML, func(f *Form) {
		fedGroup(f)["config.accept_settings_from"] = []string{"pop-b"}
		f.Blocks["federation"]["domain"] = "pop-a2"
	})
	if cfg.Mode != "observe" || cfg.Announcer != nil || len(cfg.Allowlist.Prefixes) != 1 || cfg.Allowlist.Prefixes[0] != "198.51.100.0/24" {
		t.Fatalf("mode %q, announcer %v, allowlist %v\n%s", cfg.Mode, cfg.Announcer, cfg.Allowlist.Prefixes, out)
	}
	for _, keep := range []string{"mode: observe\n", "thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}\n", "allowlist:\n  prefixes: [198.51.100.0/24]\n", "- name: keep-a\n"} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q changed or vanished:\n%s", keep, out)
		}
	}
}

func TestFederationTurnOnAndOff(t *testing.T) {
	out, cfg := fedEdit(t, observeYAML, func(f *Form) {
		f.Blocks["federation"]["domain"] = "pop-a"
		f.Blocks["federation"]["federation"] = Values{
			"type": "mtls", "config.listen": "0.0.0.0:9443",
			"config.cert_file": "/etc/packeteer/certs/pop-a.crt", "config.key_file": "/etc/packeteer/certs/pop-a.key", "config.ca_file": "/etc/packeteer/certs/ca.crt",
			"config.peers": []Values{{"name": "pop-b", "url": "https://192.0.2.20:9443"}},
		}
	})
	if cfg.Domain != "pop-a" || cfg.Federation == nil || cfg.Federation.Type != "mtls" || cfg.Mode != "observe" {
		t.Fatalf("domain %q, federation %+v, mode %q\n%s", cfg.Domain, cfg.Federation, cfg.Mode, out)
	}
	if strings.Contains(out, "accept_settings_from") {
		t.Fatalf("push was turned on by the form's defaults:\n%s", out)
	}
	off, cfg := fedEdit(t, federationYAML, func(f *Form) { f.Blocks["federation"]["federation"] = Values(nil) })
	if cfg.Federation != nil || strings.Contains(off, "federation") || strings.Contains(off, "pop-b") {
		t.Fatalf("federation stayed:\n%s", off)
	}
}

func TestFederationRefusals(t *testing.T) {
	cases := []struct {
		name string
		edit func(g Values)
		want string
	}{
		{"plain http peer", func(g Values) { g["config.peers"].([]Values)[0]["url"] = "http://192.0.2.20:9443" }, "config.peers[0].url"},
		{"peer url path", func(g Values) { g["config.peers"].([]Values)[0]["url"] = "https://192.0.2.20:9443/x" }, "https://host:port"},
		{"peer name", func(g Values) { g["config.peers"].([]Values)[0]["name"] = "pop b" }, "config.peers[0].name"},
		{"peer without name", func(g Values) { g["config.peers"].([]Values)[0]["name"] = "" }, "config.peers[0].name"},
		{"duplicate peer", func(g Values) {
			g["config.peers"] = append(g["config.peers"].([]Values), Values{"name": "pop-b", "url": "https://192.0.2.30:9443"})
		}, "duplicate pop-b"},
		{"missing key file", func(g Values) { g["config.key_file"] = "" }, "config.key_file"},
		{"relative ca file", func(g Values) { g["config.ca_file"] = "ca.crt" }, "absolute path"},
		{"listen", func(g Values) { g["config.listen"] = "9443" }, "config.listen"},
		{"accept name", func(g Values) { g["config.accept_settings_from"] = []string{"pop b"} }, "accept_settings_from[0]"},
		{"poll interval", func(g Values) { g["config.poll_interval"] = "10ms" }, "config.poll_interval"},
		{"max bytes", func(g Values) { g["config.max_bytes"] = "10" }, "config.max_bytes"},
		{"type", func(g Values) { g["type"] = "exec" }, "federation.type"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := mustParse(t, federationYAML)
			c.edit(fedGroup(&f))
			_, err := ApplyForm([]byte(federationYAML), roundTripJSON(t, f))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestFederationAdvancedKeyIsWritten(t *testing.T) {
	out, _ := fedEdit(t, federationYAML, func(f *Form) { fedGroup(f)["config.timeout"] = "500ms" })
	if !strings.Contains(out, "timeout: 500ms") {
		t.Fatalf("timeout not written:\n%s", out)
	}
}
