package mtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T, name string) ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return ca{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue writes a leaf for name (CN and DNS SAN, plus 127.0.0.1) and
// returns the cert and key paths.
func (c ca) issue(t *testing.T, dir, name string) (string, string) {
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cp, kp := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	write(t, cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	write(t, kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
	return cp, kp
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

type pki struct {
	dir, caFile string
	ca          ca
}

func newPKI(t *testing.T) pki {
	dir := t.TempDir()
	c := newCA(t, "packeteer-test-ca")
	caFile := filepath.Join(dir, "ca.crt")
	write(t, caFile, c.pem)
	return pki{dir: dir, caFile: caFile, ca: c}
}

func build(t *testing.T, raw map[string]any) (*Federation, error) {
	t.Helper()
	b, err := yaml.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var node yaml.Node
	if err := yaml.Unmarshal(b, &node); err != nil {
		t.Fatal(err)
	}
	f, err := New(plugin.NewConfig(node.Content[0]), plugin.Env{})
	if err != nil {
		return nil, err
	}
	return f.(*Federation), nil
}

func instance(t *testing.T, p pki, name string, extra map[string]any) *Federation {
	t.Helper()
	cert, key := p.ca.issue(t, p.dir, name)
	raw := map[string]any{"cert_file": cert, "key_file": key, "ca_file": p.caFile, "poll_interval": "100ms", "max_age": "300ms"}
	for k, v := range extra {
		raw[k] = v
	}
	f, err := build(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func snap(name, domain string) plugin.InstanceSnapshot {
	now := time.Now()
	return plugin.InstanceSnapshot{
		Instance: name, Domain: domain, Mode: "observe", Time: now, RIBReady: true,
		Providers: []plugin.FederatedProvider{{Name: "x-" + domain, Domain: domain, Up: true}},
		Paths: []plugin.FederatedPath{{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Provider: "x-" + domain,
			Sent: 4, RTT: 20 * time.Millisecond, Time: now.Add(-time.Second)}},
	}
}

func waitPeer(t *testing.T, f *Federation, want func(plugin.PeerState) bool) plugin.PeerState {
	t.Helper()
	var last plugin.PeerState
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		last = f.Peers(time.Now())[0]
		if want(last) {
			return last
		}
	}
	t.Fatalf("peer never reached the wanted state: %+v", last)
	return last
}

func stop(t *testing.T, f *Federation) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.Stop(ctx); err != nil {
		t.Error(err)
	}
}

// TestTwoInstances: pop-b serves, pop-a polls it over mutual TLS. When
// pop-b stops, pop-a's view of it goes stale within max_age.
func TestTwoInstances(t *testing.T) {
	p := newPKI(t)
	b := instance(t, p, "pop-b", map[string]any{"listen": "127.0.0.1:0", "allow_clients": []string{"pop-a"}})
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.Publish(snap("pop-b", "pop-b"))
	a := instance(t, p, "pop-a", map[string]any{"peers": []map[string]any{{"name": "pop-b", "url": "https://" + b.Addr().String(), "server_name": "pop-b"}}})
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer stop(t, a)

	got := waitPeer(t, a, func(s plugin.PeerState) bool { return s.Fresh })
	if got.Snapshot.Domain != "pop-b" || len(got.Snapshot.Paths) != 1 || got.Error != "" {
		t.Fatalf("peer = %+v", got)
	}
	if age := got.LastSeen.Sub(got.Snapshot.Paths[0].Time); age < 900*time.Millisecond || age > 2*time.Second {
		t.Fatalf("path age %s, want about 1s as pop-b measured it", age)
	}

	stop(t, b)
	got = waitPeer(t, a, func(s plugin.PeerState) bool { return !s.Fresh })
	if got.Error == "" {
		t.Fatalf("stale peer has no error: %+v", got)
	}
}

func TestRefusesUnknownClientAndWrongInstance(t *testing.T) {
	p := newPKI(t)
	b := instance(t, p, "pop-b", map[string]any{"listen": "127.0.0.1:0", "allow_clients": []string{"pop-a"}})
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer stop(t, b)
	b.Publish(snap("pop-b", "pop-b"))
	url := "https://" + b.Addr().String()

	// A certificate from the same CA that is not an allowed client.
	cert, key := p.ca.issue(t, p.dir, "intruder")
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(p.ca.pem)
	cl := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{pair}, RootCAs: pool, ServerName: "pop-b", MinVersion: tls.VersionTLS13,
	}}}
	res, err := cl.Get(url + SnapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("intruder got %s", res.Status)
	}
	// No client certificate at all: the handshake fails.
	nocert := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, ServerName: "pop-b", MinVersion: tls.VersionTLS13,
	}}}
	if res, err := nocert.Get(url + SnapshotPath); err == nil {
		res.Body.Close()
		if res.StatusCode == http.StatusOK {
			t.Fatal("served a snapshot without a client certificate")
		}
	}
	// A certificate from another CA is refused.
	other := newCA(t, "other-ca")
	ocert, okey := other.issue(t, t.TempDir(), "pop-a")
	opair, _ := tls.LoadX509KeyPair(ocert, okey)
	foreign := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{opair}, RootCAs: pool, ServerName: "pop-b", MinVersion: tls.VersionTLS13,
	}}}
	if res, err := foreign.Get(url + SnapshotPath); err == nil {
		res.Body.Close()
		if res.StatusCode == http.StatusOK {
			t.Fatal("served a snapshot to a certificate from another CA")
		}
	}

	// pop-a expects the instance at that URL to be pop-c: refused.
	a := instance(t, p, "pop-a", map[string]any{"peers": []map[string]any{{"name": "pop-c", "url": url, "server_name": "pop-b"}}})
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer stop(t, a)
	got := waitPeer(t, a, func(s plugin.PeerState) bool { return s.Error != "" })
	if got.Fresh || !strings.Contains(got.Error, `instance "pop-b", want "pop-c"`) {
		t.Fatalf("peer = %+v", got)
	}
}

func TestConfigErrors(t *testing.T) {
	p := newPKI(t)
	cert, key := p.ca.issue(t, p.dir, "pop-a")
	base := func() map[string]any {
		return map[string]any{"cert_file": cert, "key_file": key, "ca_file": p.caFile,
			"peers": []map[string]any{{"name": "pop-b", "url": "https://192.0.2.20:9443"}}}
	}
	cases := []struct {
		name, key string
		val       any
		want      string
	}{
		{"no tls", "cert_file", "", "cert_file, key_file, and ca_file are required"},
		{"missing file", "ca_file", filepath.Join(p.dir, "nope"), "ca_file"},
		{"http url", "peers", []map[string]any{{"name": "pop-b", "url": "http://192.0.2.20:9443"}}, "must be https://host:port"},
		{"url path", "peers", []map[string]any{{"name": "pop-b", "url": "https://192.0.2.20:9443/x"}}, "must be https://host:port"},
		{"dup peer", "peers", []map[string]any{{"name": "pop-b", "url": "https://192.0.2.20:9443"}, {"name": "pop-b", "url": "https://192.0.2.21:9443"}}, "duplicate name"},
		{"bad name", "peers", []map[string]any{{"name": "-b", "url": "https://192.0.2.20:9443"}}, "name"},
		{"no peers or listen", "peers", []map[string]any{}, "need listen, peers, or both"},
		{"poll too fast", "poll_interval", "10ms", "poll_interval"},
		{"max_age below poll", "max_age", "1s", "max_age"},
		{"unknown key", "bogus", 1, "bogus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := base()
			raw[tc.key] = tc.val
			_, err := build(t, raw)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := build(t, base()); err != nil {
		t.Fatalf("valid config: %v", err)
	}
}
