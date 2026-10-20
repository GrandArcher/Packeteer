package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/internal/federation"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/plugins/federation/mtls"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// memAudit keeps audit records in memory.
type memAudit struct {
	mu   sync.Mutex
	recs []plugin.AuditRecord
}

func (m *memAudit) AppendAudit(_ context.Context, r plugin.AuditRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs = append(m.recs, r)
	return nil
}

func (m *memAudit) Audit(context.Context, plugin.AuditQuery) ([]plugin.AuditRecord, error) {
	return nil, nil
}

func (m *memAudit) byAction(action string) []plugin.AuditRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []plugin.AuditRecord
	for _, r := range m.recs {
		if r.Action == action {
			out = append(out, r)
		}
	}
	return out
}

// pushPKI writes a CA and one leaf certificate per instance name into dir.
type pushPKI struct {
	dir string
	ca  *x509.Certificate
	key *ecdsa.PrivateKey
}

func newPushPKI(t *testing.T) *pushPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "packeteer-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &pushPKI{dir: t.TempDir(), ca: ca, key: key}
	p.write("ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return p
}

func (p *pushPKI) write(name string, b []byte) string {
	path := filepath.Join(p.dir, name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		panic(err)
	}
	return path
}

func (p *pushPKI) issue(t *testing.T, name string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	p.write(name+".crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	p.write(name+".key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
}

// pushPOP is one instance: a config file under a real editor, an mtls
// transport, and a stand-in for the online reload that loads the file and
// makes it the running config.
type pushPOP struct {
	name    string
	path    string
	fed     *fedState
	plug    plugin.Federation
	editor  *configedit.Editor
	audit   *memAudit
	auditor *auth.Auditor

	mu      sync.Mutex
	applies int
	running *config.Config
	refuse  error
}

const pushPOPYAML = `mode: observe
asn: 64512
router_id: 192.0.2.10
domain: %[1]s
instance: %[1]s
thresholds:
  min_loss_delta_pct: 1
  min_rtt_delta_ms: 15
providers:
  - {name: x-%[1]s, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
allowlist:
  prefixes: [198.51.100.0/24]
http: {listen: "", config_editor: true}
federation:
  type: mtls
  config:
    listen: 127.0.0.1:0
    cert_file: %[2]s/%[1]s.crt
    key_file: %[2]s/%[1]s.key
    ca_file: %[2]s/ca.crt
    allow_clients: [pop-a, pop-b]
    accept_settings_from: [%[3]s]
    peers:
      - {name: %[4]s, url: "https://192.0.2.20:9443"}
`

func newPushPOP(t *testing.T, p *pushPKI, name, other string, audit *memAudit) *pushPOP {
	t.Helper()
	p.issue(t, name)
	pop := &pushPOP{name: name, audit: audit}
	pop.path = filepath.Join(t.TempDir(), "config.yaml")
	text := fmt.Sprintf(pushPOPYAML, name, p.dir, other, other)
	if err := os.WriteFile(pop.path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(pop.path)
	if err != nil {
		t.Fatal(err)
	}
	pop.running = cfg
	pop.editor, err = newConfigEditor(cfg, pop.path, noEnv, "", false)
	if err != nil {
		t.Fatal(err)
	}
	pop.auditor = auth.NewAuditor(audit, nil, nil)
	return pop
}

// start builds the transport on a free port, with the peer's address set
// once it is known.
func (pop *pushPOP) start(t *testing.T, p *pushPKI, peer *pushPOP) {
	t.Helper()
	raw := map[string]any{
		"listen": "127.0.0.1:0", "cert_file": filepath.Join(p.dir, pop.name+".crt"), "key_file": filepath.Join(p.dir, pop.name+".key"),
		"ca_file": filepath.Join(p.dir, "ca.crt"), "allow_clients": []string{"pop-a", "pop-b"},
		"accept_settings_from": []string{peerName(pop.name)}, "poll_interval": "200ms",
	}
	if peer != nil {
		raw["peers"] = []map[string]any{{"name": peer.name, "url": "https://" + peer.plug.(*mtls.Federation).Addr().String(), "server_name": peer.name}}
	}
	b, err := yaml.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var node yaml.Node
	if err := yaml.Unmarshal(b, &node); err != nil {
		t.Fatal(err)
	}
	pop.plug, err = mtls.New(plugin.NewConfig(node.Content[0]), plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if err := pop.plug.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pop.plug.Stop(context.Background()) })
}

func peerName(n string) string {
	if n == "pop-a" {
		return "pop-b"
	}
	return "pop-a"
}

// wire connects the fedState to the transport the way daemon does.
func (pop *pushPOP) wire(t *testing.T) {
	t.Helper()
	pop.fed = &fedState{fed: pop.plug}
	pop.fed.editor = pop.editor
	pop.fed.acceptSettings(func(context.Context) ([]string, error, error) {
		pop.mu.Lock()
		defer pop.mu.Unlock()
		pop.applies++
		if pop.refuse != nil {
			return nil, pop.refuse, nil
		}
		next, err := config.Load(pop.path)
		if err != nil {
			return nil, err, nil
		}
		_, online := classify(pop.running, next)
		pop.running = next
		pop.editor.SetRunning(next)
		return online, nil, nil
	}, pop.auditor)
}

func (pop *pushPOP) file(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(pop.path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (pop *pushPOP) setFile(t *testing.T, text string) {
	t.Helper()
	if err := os.WriteFile(pop.path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (pop *pushPOP) runningThreshold() float64 {
	pop.mu.Lock()
	defer pop.mu.Unlock()
	return pop.running.Thresholds.MinLossDeltaPct
}

func (pop *pushPOP) applyCount() int {
	pop.mu.Lock()
	defer pop.mu.Unlock()
	return pop.applies
}

func onlyPeer(t *testing.T, r federation.PushReport) federation.PeerPush {
	t.Helper()
	if len(r.Peers) != 1 {
		t.Fatalf("report = %+v", r)
	}
	return r.Peers[0]
}

// Two POPs over real mutual TLS (#137): pop-a pushes a threshold, both end
// up running it, the change is audited on both, and pop-b refuses an
// invalid section, a section that is not pushable, a file with other
// pending edits, and a refused online apply, leaving its file as it was.
func TestFederationSettingsPush(t *testing.T) {
	pki := newPushPKI(t)
	auditA, auditB := &memAudit{}, &memAudit{}
	a := newPushPOP(t, pki, "pop-a", "pop-b", auditA)
	b := newPushPOP(t, pki, "pop-b", "pop-a", auditB)
	b.start(t, pki, nil)
	a.start(t, pki, b)
	a.wire(t)
	b.wire(t)
	ctx := context.Background()

	// The operator sets the threshold on pop-a, applies it there, and pushes.
	edited := strings.Replace(a.file(t), "min_loss_delta_pct: 1", "min_loss_delta_pct: 3", 1)
	if _, _, err := a.editor.Save([]byte(edited), configedit.Hash([]byte(a.file(t))), false); err != nil {
		t.Fatal(err)
	}
	next, err := config.Load(a.path)
	if err != nil {
		t.Fatal(err)
	}
	a.running = next
	a.editor.SetRunning(next)

	// The HTTP endpoint is the admin entry point and audits on pop-a.
	srv, err := httpapi.New(httpapi.Options{
		Snapshot: func() httpapi.Snapshot { return httpapi.Snapshot{} }, User: "admin", Password: "pw",
		Audit: a.auditor, ConfigEditor: a.editor, FederationPush: a.fed.push,
	})
	if err != nil {
		t.Fatal(err)
	}
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/federation/push", strings.NewReader(body))
		req.SetBasicAuth("admin", "pw")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	rec := post(`{"sections":["thresholds"]}`)
	var rep federation.PushReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("push: %d %s", rec.Code, rec.Body)
	}
	if got := onlyPeer(t, rep); !rep.OK || got.Peer != "pop-b" || got.Status != plugin.SettingsApplied || len(got.Applied) != 1 || got.Applied[0] != "thresholds" {
		t.Fatalf("report = %+v", rep)
	}
	if a.runningThreshold() != 3 || b.runningThreshold() != 3 {
		t.Fatalf("running thresholds: a=%v b=%v, want both 3", a.runningThreshold(), b.runningThreshold())
	}
	if !strings.Contains(b.file(t), "min_loss_delta_pct: 3") || !strings.Contains(b.file(t), "mode: observe") {
		t.Fatalf("pop-b file:\n%s", b.file(t))
	}
	// Audit on both sides.
	if recs := auditB.byAction("federation.settings"); len(recs) != 1 || recs[0].Actor != "pop-a" || recs[0].Method != auth.MethodFederation || recs[0].Role != "" ||
		recs[0].Result != auth.ResultOK || recs[0].Target != "thresholds" || !strings.Contains(recs[0].Detail, "applied") {
		t.Fatalf("pop-b audit = %+v", auditB.recs)
	}
	var sent *plugin.AuditRecord
	for _, r := range auditA.recs {
		if r.Target == "federation" && r.Action == "POST /api/federation/push" {
			sent = &r
		}
	}
	if sent == nil || sent.Actor != "admin" || !strings.Contains(sent.Detail, "pop-b=applied") {
		t.Fatalf("pop-a audit = %+v", auditA.recs)
	}

	// The same push again changes nothing and applies nothing.
	before := b.applyCount()
	rec = post(`{"sections":["thresholds"],"peers":["pop-b"]}`)
	_ = json.Unmarshal(rec.Body.Bytes(), &rep)
	if got := onlyPeer(t, rep); got.Status != plugin.SettingsUnchanged || b.applyCount() != before {
		t.Fatalf("repeat push: %+v, applies %d -> %d", got, before, b.applyCount())
	}

	// A section the sender's file does not have is not pushed: it would
	// reset every peer's key to the default.
	if rec := post(`{"sections":["policies"]}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "no policies section") {
		t.Fatalf("absent section: %d %s", rec.Code, rec.Body)
	}

	// pop-b's file holds a saved edit that never ran: a push of the same
	// text is applied, not reported as unchanged.
	savedOnly := strings.Replace(b.file(t), "min_loss_delta_pct: 3", "min_loss_delta_pct: 6", 1)
	b.setFile(t, savedOnly)
	before = b.applyCount()
	res0, err := a.plug.Push(ctx, "pop-b", plugin.SettingsPush{Sections: map[string]string{"thresholds": "min_loss_delta_pct: 6\nmin_rtt_delta_ms: 15\n"}})
	if err != nil || res0.Status != plugin.SettingsApplied || b.applyCount() != before+1 || b.runningThreshold() != 6 {
		t.Fatalf("saved but not applied: %+v, %v, running %v", res0, err, b.runningThreshold())
	}
	res0, err = a.plug.Push(ctx, "pop-b", plugin.SettingsPush{Sections: map[string]string{"thresholds": "min_loss_delta_pct: 3\nmin_rtt_delta_ms: 15\n"}})
	if err != nil || res0.Status != plugin.SettingsApplied || b.runningThreshold() != 3 {
		t.Fatalf("back to 3: %+v, %v", res0, err)
	}

	// Refusals leave pop-b's file and running config alone.
	fileBefore := b.file(t)
	refusals := []struct {
		name     string
		sections map[string]string
		want     string
	}{
		{"mode", map[string]string{"mode": "inject\n"}, `section "mode" cannot be pushed`},
		{"allowlist", map[string]string{"allowlist": "prefixes: [203.0.113.0/24]\n"}, `section "allowlist" cannot be pushed`},
		{"announcer", map[string]string{"announcer": "type: gobgp\n"}, `section "announcer" cannot be pushed`},
		{"bgp", map[string]string{"bgp": "neighbors: []\n"}, `section "bgp" cannot be pushed`},
		{"invalid threshold", map[string]string{"thresholds": "min_loss_delta_pct: -4\n"}, "min_loss_delta_pct"},
		{"unknown threshold key", map[string]string{"thresholds": "min_loss_delta_pct: 3\nbogus: 1\n"}, "bogus"},
		{"mixed with a bad section", map[string]string{"thresholds": "min_loss_delta_pct: 9\n", "mode": "inject\n"}, `section "mode" cannot be pushed`},
		{"exec policy", map[string]string{"policies": "- type: exec\n  config: {command: /bin/true}\n"}, "exec"},
		{"empty", map[string]string{}, "no sections"},
	}
	for _, tc := range refusals {
		res, err := a.plug.Push(ctx, "pop-b", plugin.SettingsPush{Sections: tc.sections})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if res.Status != plugin.SettingsRefused || !strings.Contains(strings.Join(res.Errors, "\n"), tc.want) {
			t.Errorf("%s: result = %+v, want a refusal naming %q", tc.name, res, tc.want)
		}
	}
	if b.file(t) != fileBefore || b.runningThreshold() != 3 || b.running.Mode != config.ModeObserve {
		t.Fatalf("a refused push changed pop-b:\n%s", b.file(t))
	}
	denied := 0
	for _, r := range auditB.byAction("federation.settings") {
		if r.Result == auth.ResultDenied {
			denied++
		}
	}
	if denied != len(refusals) {
		t.Fatalf("pop-b audited %d denied pushes, want %d", denied, len(refusals))
	}

	// An invalid section sent through the API shows per peer.
	a.setFile(t, strings.Replace(a.file(t), "min_loss_delta_pct: 3", "min_loss_delta_pct: -4", 1))
	rec = post(`{"sections":["thresholds"]}`)
	_ = json.Unmarshal(rec.Body.Bytes(), &rep)
	if got := onlyPeer(t, rep); rep.OK || got.Status != plugin.SettingsRefused || !strings.Contains(strings.Join(got.Errors, ""), "min_loss_delta_pct") {
		t.Fatalf("invalid section: %+v", rep)
	}
	a.setFile(t, strings.Replace(a.file(t), "min_loss_delta_pct: -4", "min_loss_delta_pct: 4", 1))

	// Another pending edit in pop-b's file: not applied, so not pushed along.
	b.setFile(t, strings.Replace(fileBefore, "providers:", "hold_time: 7m\nproviders:", 1))
	res, err := a.plug.Push(ctx, "pop-b", plugin.SettingsPush{Sections: map[string]string{"thresholds": "min_loss_delta_pct: 4\n"}})
	if err != nil || res.Status != plugin.SettingsRefused || !strings.Contains(strings.Join(res.Errors, ""), "hold_time") {
		t.Fatalf("pending edit: %+v, %v", res, err)
	}
	b.setFile(t, fileBefore)

	// An online apply that pop-b refuses puts its file back.
	b.mu.Lock()
	b.refuse = errors.New("probe loop busy")
	b.mu.Unlock()
	res, err = a.plug.Push(ctx, "pop-b", plugin.SettingsPush{Sections: map[string]string{"thresholds": "min_loss_delta_pct: 4\n"}})
	if err != nil || res.Status != plugin.SettingsRefused || !strings.Contains(strings.Join(res.Errors, ""), "probe loop busy") {
		t.Fatalf("refused apply: %+v, %v", res, err)
	}
	if b.file(t) != fileBefore || b.runningThreshold() != 3 {
		t.Fatalf("pop-b file after a refused apply:\n%s", b.file(t))
	}
	b.mu.Lock()
	b.refuse = nil
	b.mu.Unlock()

	// The peer's policies travel too, and a peer that is down is reported.
	policies := "- type: rules\n  config:\n    rules:\n      - {name: skip, action: ignore, prefixes: [192.0.2.0/24]}\n"
	res, err = a.plug.Push(ctx, "pop-b", plugin.SettingsPush{Sections: map[string]string{"policies": policies}})
	if err != nil || res.Status != plugin.SettingsApplied || !strings.Contains(b.file(t), "name: skip") {
		t.Fatalf("policies: %+v, %v\n%s", res, err, b.file(t))
	}
	if err := b.plug.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	rec = post(`{"sections":["thresholds"]}`)
	_ = json.Unmarshal(rec.Body.Bytes(), &rep)
	if got := onlyPeer(t, rep); rep.OK || got.Status != federation.Unreachable {
		t.Fatalf("dead peer: %+v", rep)
	}
	if rec := post(`{"sections":["mode"]}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "cannot be pushed") {
		t.Fatalf("mode through the API: %d %s", rec.Code, rec.Body)
	}
	if rec := post(`{"sections":["thresholds"],"peers":["pop-z"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown peer: %d %s", rec.Code, rec.Body)
	}
}
