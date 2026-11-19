package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/herd"
)

// keyFile writes a PKCS#8 Ed25519 key and returns the node the daemon
// loads from it.
func keyFile(t *testing.T, path string) *herd.Node {
	t.Helper()
	n, err := herd.LoadNode(path)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// clientCert is a self-signed client certificate over the key in path.
func clientCert(t *testing.T, path string) tls.Certificate {
	t.Helper()
	b, _ := os.ReadFile(path)
	blk, _ := pem.Decode(b)
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	priv := k.(ed25519.PrivateKey)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func entry(t *testing.T, n *herd.Node, asn uint32, url string) []byte {
	t.Helper()
	raw, err := n.SignEntry(herd.Entry{ASN: asn, Nodes: []herd.EntryNode{{Key: n.PublicKey(), URL: url}}, RetentionDays: 90,
		Classes: []string{"measurements"}, Issued: time.Now().Add(-time.Minute), Expires: time.Now().Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The seed node relays every entry file as is, bad ones too, signed in a
// peer list; only the keys of entries that verify may connect.
func TestSeedNodeRelaysEveryEntryToPinnedMembersOnly(t *testing.T) {
	dir := t.TempDir()
	keys, relay := filepath.Join(dir, "keys"), filepath.Join(dir, "relay")
	if err := os.MkdirAll(relay, 0o755); err != nil {
		t.Fatal(err)
	}
	seed := keyFile(t, filepath.Join(keys, "d.key"))
	a := keyFile(t, filepath.Join(keys, "a.key"))
	stranger := keyFile(t, filepath.Join(keys, "x.key"))
	good := entry(t, a, 64496, "https://192.0.2.10:9444")
	tampered := bytes.Replace(good, []byte("192.0.2.10"), []byte("192.0.2.14"), 1)
	for name, b := range map[string][]byte{"64496.json": good, "tampered.json": tampered, "junk.json": []byte("not json")} {
		if err := os.WriteFile(filepath.Join(relay, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(dir, "d.yaml")
	y := `mode: observe
asn: 64499
router_id: 192.0.2.20
providers: [{name: up, source_ip: 192.0.2.20, next_hop: 192.0.2.21}]
bgp: {neighbors: [{address: 192.0.2.251}]}
storage: {type: sqlite}
herd:
  enabled: true
  share: {classes: [measurements]}
  vantage: {country: FR}
  listen: 127.0.0.1:0
  key_file: ` + filepath.Join(keys, "d.key") + `
  hub: {url: "https://herd-hub:8443/herd.json"}
`
	if err := os.WriteFile(cfg, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	srv, err := startRelay(cfg, relay, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	url := "https://" + srv.Addr().String() + herd.PathPeers
	cli := func(key string) *http.Client {
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, Certificates: []tls.Certificate{clientCert(t, filepath.Join(keys, key))},
		}}}
	}
	if res, err := cli("x.key").Get(url); err == nil {
		res.Body.Close()
		t.Fatalf("a key no entry lists connected: %d (%s)", res.StatusCode, stranger.ID())
	}
	res, err := cli("a.key").Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	var l herd.PeerList
	if res.StatusCode != http.StatusOK || json.Unmarshal(body, &l) != nil || l.Member != seed.ID() || l.Signature == "" {
		t.Fatalf("peer list: %d %s", res.StatusCode, body)
	}
	if len(l.Entries) != 2 || !strings.Contains(string(l.Entries[0].Entry), "192.0.2.10") || !strings.Contains(string(l.Entries[1].Entry), "192.0.2.14") {
		t.Errorf("relayed %d entries, want the good and the tampered one as is: %s", len(l.Entries), body)
	}
}
