package snippet

import (
	"errors"
	"strings"
	"testing"
)

func wizardAnswers() Answers {
	return Answers{Wizard: true, ASN: 64496, RouterID: "192.0.2.10", Edge: "192.0.2.254"}
}

// A first run: nothing is saved, and the answers typed in setup step 1 are
// enough for a snippet. The community follows the wizard's own rule.
func TestForCandidateFromWizardAnswersAlone(t *testing.T) {
	ps, err := ForCandidate(nil, wizardAnswers())
	if err != nil {
		t.Fatal(err)
	}
	want := Params{ASN: 64496, Router: "192.0.2.254", Packeteer: "192.0.2.10", Community: "64496:666"}
	if len(ps) != 1 || ps[0] != want {
		t.Fatalf("params = %+v, want %+v", ps, want)
	}
	text, err := Join(FRR, ps)
	if err != nil || !strings.Contains(text, "bgp community-list standard packeteer permit 64496:666") || !strings.Contains(text, "router bgp 64496") {
		t.Fatalf("frr = %q, %v", text, err)
	}
}

func TestForCandidateFlowStep(t *testing.T) {
	a := wizardAnswers()
	a.FlowListen = ":2055"
	ps, err := ForCandidate(nil, a)
	if err != nil {
		t.Fatal(err)
	}
	if ps[0].FlowHost != "192.0.2.10" || ps[0].FlowPort != 2055 {
		t.Fatalf("collector = %s:%d", ps[0].FlowHost, ps[0].FlowPort)
	}
	text, err := Generate(MikroTik, ps[0])
	if err != nil || !strings.Contains(text, "dst-address=192.0.2.10 port=2055") {
		t.Fatalf("mikrotik = %q, %v", text, err)
	}
}

const exampleText = `asn: 64496
router_id: 192.0.2.10
packeteer_community: "64512:666"
bgp:
  neighbors:
    - address: 192.0.2.253
      add_path: true
    - address: 192.0.2.252
sources:
  - type: flow
    config:
      listen: "192.0.2.10:6343"
providers:
  - name: transit-v6
    source_ip: 2001:db8::11
    next_hop: 2001:db8::1
`

// With the wizard closed the text is what will run, so it is used as it is.
func TestForCandidateTextAlone(t *testing.T) {
	ps, err := ForCandidate([]byte(exampleText), Answers{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 {
		t.Fatalf("%d params, want one per neighbor", len(ps))
	}
	want := Params{ASN: 64496, Router: "192.0.2.253", Packeteer: "192.0.2.10", Community: "64512:666", AddPath: true, IPv6: true, FlowHost: "192.0.2.10", FlowPort: 6343}
	if ps[0] != want {
		t.Fatalf("params = %+v, want %+v", ps[0], want)
	}
	if ps[1].Router != "192.0.2.252" || ps[1].AddPath {
		t.Fatalf("second neighbor = %+v", ps[1])
	}
}

// While the wizard is open Generate replaces asn, router_id, the community,
// the neighbors, and the sources, so the snippet must show those and not the
// text: a router filter on 64512:666 would reject routes saved as 64496:666.
func TestForCandidateWizardOwnsItsKeys(t *testing.T) {
	ps, err := ForCandidate([]byte(exampleText), Answers{Wizard: true, ASN: 64496, RouterID: "192.0.2.10", Edge: "192.0.2.254"})
	if err != nil {
		t.Fatal(err)
	}
	want := Params{ASN: 64496, Router: "192.0.2.254", Packeteer: "192.0.2.10", Community: "64496:666", IPv6: true}
	if len(ps) != 1 || ps[0] != want {
		t.Fatalf("params = %+v, want %+v", ps, want)
	}
	ps, err = ForCandidate([]byte(exampleText), Answers{Wizard: true, ASN: 64496, RouterID: "192.0.2.10", Edge: "192.0.2.254", FlowListen: "192.0.2.20:2055"})
	if err != nil {
		t.Fatal(err)
	}
	want.FlowHost, want.FlowPort = "192.0.2.20", 2055
	if len(ps) != 1 || ps[0] != want {
		t.Fatalf("with flow: %+v, want %+v", ps, want)
	}
}

func TestForCandidateMissingAnswers(t *testing.T) {
	cases := []struct {
		name string
		text string
		a    Answers
		want []string
	}{
		{"nothing yet", "", Answers{Wizard: true}, []string{"AS number: enter it as ASN in setup step 1", "Router address: enter the Edge address in setup step 1", "Packeteer community:", "Packeteer's address: enter the Router ID in setup step 1"}},
		{"only the AS number", "", Answers{Wizard: true, ASN: 64496}, []string{"Router address: enter the Edge address in setup step 1", "Packeteer's address: enter the Router ID in setup step 1"}},
		{"no router id", "", Answers{Wizard: true, ASN: 64496, Edge: "192.0.2.254"}, []string{"Packeteer's address: enter the Router ID in setup step 1"}},
		{"32-bit AS number", "", Answers{Wizard: true, ASN: 65536, RouterID: "192.0.2.10", Edge: "192.0.2.254"}, []string{"above 65535"}},
	}
	for _, c := range cases {
		_, err := ForCandidate([]byte(c.text), c.a)
		var miss *MissingError
		if !errors.As(err, &miss) {
			t.Fatalf("%s: err = %v, want a *MissingError", c.name, err)
		}
		if len(miss.Hints) != len(c.want) {
			t.Fatalf("%s: %d hints, want %d: %q", c.name, len(miss.Hints), len(c.want), miss.Hints)
		}
		for i, w := range c.want {
			if !strings.Contains(miss.Hints[i], w) {
				t.Errorf("%s: hint %d = %q, want %q in it", c.name, i, miss.Hints[i], w)
			}
		}
		if strings.Contains(err.Error(), "no bgp.neighbors") || strings.Contains(err.Error(), "is not set:") {
			t.Errorf("%s: raw key error leaked: %v", c.name, err)
		}
	}
}

func TestForCandidateRefusals(t *testing.T) {
	if _, err := ForCandidate([]byte("asn: [1"), Answers{}); err == nil || !strings.Contains(err.Error(), "does not parse") {
		t.Errorf("bad yaml: %v", err)
	}
	a := wizardAnswers()
	a.Edge = "edge"
	if _, err := ForCandidate(nil, a); err == nil || !strings.Contains(err.Error(), `bgp.neighbors address "edge"`) {
		t.Errorf("bad edge: %v", err)
	}
}
