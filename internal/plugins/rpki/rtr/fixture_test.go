package rtr

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// recording is one RTR cache's recorded answers (testdata/README.md): the
// response to a Reset Query, the Serial Notify it sent after the ROA set
// changed, and the response to the Serial Query that followed.
type recording struct {
	reset, notify, serial []byte
}

func loadRecording(t *testing.T, cache string) recording {
	t.Helper()
	read := func(kind string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", cache+"-"+kind+".bin"))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return recording{reset: read("reset"), notify: read("notify"), serial: read("serial")}
}

// endOfData returns the session ID and serial of the last End of Data PDU
// in a recorded response.
func endOfData(t *testing.T, b []byte) (uint16, uint32) {
	t.Helper()
	pdus, rest, err := splitPDUs(b)
	if err != nil || len(rest) != 0 {
		t.Fatalf("recording does not split into PDUs: %v", err)
	}
	last := pdus[len(pdus)-1]
	if last[1] != pduEndOfData {
		t.Fatalf("recording ends with PDU type %d", last[1])
	}
	return binary.BigEndian.Uint16(last[2:4]), binary.BigEndian.Uint32(last[8:12])
}

// replay plays a recording to one client: the reset response, the Serial
// Notify when proceed is closed, and the serial response to a Serial Query
// that names the recorded session and serial. Anything else fails the test
// through errs.
func replay(rw io.ReadWriter, rec recording, session uint16, serial uint32, proceed <-chan struct{}, errs chan<- error) {
	head := make([]byte, 8)
	if _, err := io.ReadFull(rw, head); err != nil || head[1] != pduResetQuery {
		errs <- fmt.Errorf("want a Reset Query, got %v %v", head, err)
		return
	}
	if _, err := rw.Write(rec.reset); err != nil {
		errs <- err
		return
	}
	<-proceed
	if _, err := rw.Write(rec.notify); err != nil {
		errs <- err
		return
	}
	q := make([]byte, 12)
	if _, err := io.ReadFull(rw, q); err != nil {
		errs <- err
		return
	}
	if q[1] != pduSerialQuery || binary.BigEndian.Uint16(q[2:4]) != session || binary.BigEndian.Uint32(q[8:12]) != serial {
		errs <- fmt.Errorf("serial query = %v, want session %d serial %d", q, session, serial)
		return
	}
	if _, err := rw.Write(rec.serial); err != nil {
		errs <- err
		return
	}
	errs <- nil
	_, _ = io.Copy(io.Discard, rw)
}

func newClient(t *testing.T, yaml string) *Client {
	t.Helper()
	cfg, err := plugin.ConfigFromYAML(yaml)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{Name: "rpki-lab"})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Client)
	if err := c.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := contextWithTimeout(2 * time.Second)
		defer cancel()
		_ = c.Stop(ctx)
	})
	return c
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(what)
}

// checkRecording asserts what the recorded ROA sets mean: before the
// change 192.0.2.0/24-24 AS64496, 203.0.113.0/24-25 AS64497, and
// 2001:db8::/32-48 AS64498; after it AS64497 is gone and
// 198.51.100.0/24-24 AS64499 is added.
func checkRecording(t *testing.T, c *Client, proceed chan<- struct{}, errs <-chan error) {
	t.Helper()
	want := func(prefix string, origin uint32, v plugin.RPKIValidity) {
		t.Helper()
		if got := c.Validate(mustPrefix(t, prefix), origin); got != v {
			t.Fatalf("%s AS%d = %q, want %q", prefix, origin, got, v)
		}
	}
	waitFor(t, "client never loaded the reset response", func() bool { return c.Status().Up })
	want("192.0.2.0/24", 64496, plugin.RPKIValid)
	want("192.0.2.0/24", 64511, plugin.RPKIInvalid)
	want("203.0.113.0/25", 64497, plugin.RPKIValid)
	want("203.0.113.0/26", 64497, plugin.RPKIInvalid)
	want("198.51.100.0/24", 64499, plugin.RPKINotFound)
	want("2001:db8:1::/48", 64498, plugin.RPKIValid)
	close(proceed)
	select {
	case err := <-errs:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client never sent the Serial Query")
	}
	waitFor(t, "serial delta never applied", func() bool {
		return c.Validate(mustPrefix(t, "198.51.100.0/24"), 64499) == plugin.RPKIValid
	})
	want("203.0.113.0/24", 64497, plugin.RPKINotFound)
	want("192.0.2.0/24", 64496, plugin.RPKIValid)
	if st := c.Status(); st.VRPs != 3 || st.Stale || st.Error != "" {
		t.Fatalf("status after delta = %+v", st)
	}
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// #200: the client loads and follows the RTR answers recorded from
// Routinator, StayRTR, and FORT. rpki-client has no RTR server; its JSON
// output is tested by the json source.
func TestRecordedCaches(t *testing.T) {
	for _, cache := range []string{"routinator", "stayrtr", "fort"} {
		t.Run(cache, func(t *testing.T) {
			rec := loadRecording(t, cache)
			session, serial := endOfData(t, rec.reset)
			ln := listen(t)
			errs := make(chan error, 1)
			proceed := make(chan struct{})
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					errs <- err
					return
				}
				defer conn.Close()
				replay(conn, rec, session, serial, proceed, errs)
			}()
			c := newClient(t, "address: "+ln.Addr().String()+"\nrefresh: 1m\n")
			checkRecording(t, c, proceed, errs)
		})
	}
}

// testCA is a throwaway CA and a server certificate for localhost.
func testCA(t *testing.T) (caPEM []byte, server tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rtr test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "rtr.lab.test"},
		DNSNames:  []string{"rtr.lab.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// #200: RTR over TLS (RFC 8210 section 9.2) checks the server against
// tls.ca_file and tls.server_name, then runs the same session. A server
// signed by another CA never loads.
func TestClientTLS(t *testing.T) {
	caPEM, cert := testCA(t)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	rec := loadRecording(t, "routinator")
	session, serial := endOfData(t, rec.reset)
	ln := tls.NewListener(listen(t), &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	errs := make(chan error, 4)
	proceed := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				replay(conn, rec, session, serial, proceed, errs)
			}()
		}
	}()
	c := newClient(t, "address: "+ln.Addr().String()+"\nrefresh: 1m\ntls:\n  ca_file: "+caFile+"\n  server_name: rtr.lab.test\n")
	checkRecording(t, c, proceed, errs)

	otherCA, _ := testCA(t)
	otherFile := filepath.Join(dir, "other.pem")
	if err := os.WriteFile(otherFile, otherCA, 0o600); err != nil {
		t.Fatal(err)
	}
	bad := newClient(t, "address: "+ln.Addr().String()+"\nrefresh: 1m\ntls:\n  ca_file: "+otherFile+"\n  server_name: rtr.lab.test\n")
	waitFor(t, "untrusted server never reported", func() bool { return strings.Contains(bad.Status().Error, "certificate") })
	if st := bad.Status(); st.Up || st.VRPs != 0 {
		t.Fatalf("untrusted server loaded: %+v", st)
	}
}

// sshServer serves the rpki-rtr subsystem to clients that log in with
// clientKey, replaying rec on each session.
func sshServer(t *testing.T, clientKey ssh.PublicKey, rec recording, proceed <-chan struct{}, errs chan<- error) (addr string, hostKey ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() == "rpki" && bytes.Equal(key.Marshal(), clientKey.Marshal()) {
			return nil, nil
		}
		return nil, fmt.Errorf("unknown key")
	}}
	cfg.AddHostKey(signer)
	session, serial := endOfData(t, rec.reset)
	ln := listen(t)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, chReqs, err := nc.Accept()
					if err != nil {
						return
					}
					go func() {
						for r := range chReqs {
							ok := r.Type == "subsystem" && len(r.Payload) > 4 && string(r.Payload[4:]) == sshSubsystem
							_ = r.Reply(ok, nil)
							if ok {
								go replay(ch, rec, session, serial, proceed, errs)
							}
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String(), signer.PublicKey()
}

// #200: RTR over SSH (RFC 8210 section 9.1) logs in with ssh.key_file,
// checks the host key against ssh.known_hosts, and runs the rpki-rtr
// subsystem. A host key that is not in known_hosts never loads.
func TestClientSSH(t *testing.T) {
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPriv)
	if err != nil {
		t.Fatal(err)
	}
	rec := loadRecording(t, "stayrtr")
	errs := make(chan error, 4)
	proceed := make(chan struct{})
	addr, hostKey := sshServer(t, clientSigner.PublicKey(), rec, proceed, errs)
	writeKnown := func(name string, key ssh.PublicKey) string {
		host, port, _ := net.SplitHostPort(addr)
		line := "[" + host + "]:" + port + " " + string(ssh.MarshalAuthorizedKey(key))
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(line), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	known := writeKnown("known_hosts", hostKey)
	sshYAML := func(knownHosts string) string {
		return "address: " + addr + "\nrefresh: 1m\nssh:\n  user: rpki\n  key_file: " + keyFile + "\n  known_hosts: " + knownHosts + "\n"
	}
	c := newClient(t, sshYAML(known))
	checkRecording(t, c, proceed, errs)

	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(otherPriv)
	bad := newClient(t, sshYAML(writeKnown("other_hosts", otherSigner.PublicKey())))
	waitFor(t, "unknown host key never reported", func() bool { return strings.Contains(bad.Status().Error, "key mismatch") })
	if st := bad.Status(); st.Up || st.VRPs != 0 {
		t.Fatalf("unknown host loaded: %+v", st)
	}
}

// #200: the TLS and SSH blocks are checked at load time.
func TestTransportConfig(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ yaml, want string }{
		{"tls: {}\nssh: {user: rpki}\n", "not both"},
		{"tls: {ca_file: " + filepath.Join(dir, "missing.pem") + "}\n", "tls.ca_file"},
		{"tls: {ca_file: " + notPEM + "}\n", "no PEM certificate"},
		{"ssh: {user: rpki}\n", "ssh needs user, key_file, and known_hosts"},
		{"ssh: {user: rpki, key_file: " + notPEM + ", known_hosts: " + notPEM + "}\n", "ssh.key_file"},
	} {
		cfg, err := plugin.ConfigFromYAML("address: 192.0.2.1:3323\n" + tc.yaml)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := New(cfg, plugin.Env{Name: "rpki-lab"}); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: err = %v, want %q", tc.yaml, err, tc.want)
		}
	}
	cfg, err := plugin.ConfigFromYAML("address: 192.0.2.1:3323\ntls: {}\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{Name: "rpki-lab"})
	if err != nil {
		t.Fatal(err)
	}
	if tc := p.(*Client).tr.tls; tc == nil || tc.ServerName != "192.0.2.1" || tc.RootCAs != nil {
		t.Fatalf("empty tls block = %+v, want system roots and the address host", tc)
	}
}
