package smtp

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"mime/quotedprintable"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fakeServer is a minimal SMTP relay for tests. It never touches a real
// network: it listens on loopback only.
type fakeServer struct {
	ln        net.Listener
	tls       *tls.Config
	starttls  bool // offer STARTTLS
	implicit  bool // TLS from the first byte
	auth      bool // offer AUTH PLAIN
	mu        sync.Mutex
	from      string
	rcpt      []string
	data      string
	authLine  string
	sawTLS    bool
	delivered chan struct{}
}

func newFake(t *testing.T, f *fakeServer) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if f.implicit {
		ln = tls.NewListener(ln, f.tls)
	}
	f.ln = ln
	f.delivered = make(chan struct{}, 8)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeServer) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeServer) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r, w := bufio.NewReader(c), bufio.NewWriter(c)
	_, isTLS := c.(*tls.Conn)
	say := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }
	say("220 fake.example.invalid ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			w.WriteString("250-fake.example.invalid\r\n")
			if f.starttls && !isTLS {
				w.WriteString("250-STARTTLS\r\n")
			}
			if f.auth && isTLS {
				w.WriteString("250-AUTH PLAIN\r\n")
			}
			say("250 8BITMIME")
		case cmd == "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(c, f.tls)
			if err := tc.Handshake(); err != nil {
				return
			}
			c, isTLS = tc, true
			r, w = bufio.NewReader(tc), bufio.NewWriter(tc)
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			f.mu.Lock()
			f.authLine = strings.TrimSpace(line[len("AUTH PLAIN"):])
			f.mu.Unlock()
			say("235 ok")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			f.mu.Lock()
			f.from, f.sawTLS = line[len("MAIL FROM:"):], isTLS
			f.mu.Unlock()
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			f.mu.Lock()
			f.rcpt = append(f.rcpt, line[len("RCPT TO:"):])
			f.mu.Unlock()
			say("250 ok")
		case cmd == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			say("250 queued")
			f.delivered <- struct{}{}
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("502 unknown")
		}
	}
}

// testCert writes a self-signed loopback certificate and returns the TLS
// config and the PEM path.
func testCert(t *testing.T) (*tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}}, path
}

func newNotifier(t *testing.T, y string, env map[string]string) (plugin.Notifier, error) {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	return plugin.Notifiers.New(TypeName, c, plugin.Env{Getenv: func(k string) string { return env[k] }})
}

var ev = plugin.NewEvent(plugin.EventBGPSessionDown, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	"iBGP session to 192.0.2.1 is down\r\nBcc: victim@example.invalid", map[string]string{"neighbor": "192.0.2.1"})

func decodeBody(t *testing.T, data string) (headers, body string) {
	t.Helper()
	i := strings.Index(data, "\r\n\r\n")
	if i < 0 {
		t.Fatalf("no header break in %q", data)
	}
	b, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(data[i+4:])))
	if err != nil {
		t.Fatal(err)
	}
	return data[:i], string(b)
}

func TestPlainRelay(t *testing.T) {
	f := newFake(t, &fakeServer{})
	y := "host: 127.0.0.1\ntls: none\nport: " + strconv.Itoa(f.port()) + "\nfrom: packeteer@example.invalid\nto: [noc@example.invalid, oncall@example.invalid]"
	n, err := newNotifier(t, y, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasPrefix(f.from, "<packeteer@example.invalid>") || len(f.rcpt) != 2 || f.sawTLS {
		t.Fatalf("from %q rcpt %v tls %v", f.from, f.rcpt, f.sawTLS)
	}
	hdr, body := decodeBody(t, f.data)
	if strings.Contains(hdr, "\r\nBcc:") {
		t.Fatalf("header injection: %q", hdr)
	}
	for _, want := range []string{"Subject: [packeteer] [CRITICAL] bgp.session_down: iBGP session to 192.0.2.1 is down  Bcc:", "X-Packeteer-Event: bgp.session_down", "To: noc@example.invalid, oncall@example.invalid"} {
		if !strings.Contains(hdr, want) {
			t.Errorf("headers missing %q:\n%s", want, hdr)
		}
	}
	if !strings.Contains(body, "neighbor: 192.0.2.1") || !strings.Contains(body, "kind: bgp.session_down") {
		t.Errorf("body:\n%s", body)
	}
}

func TestStartTLSWithAuth(t *testing.T) {
	tc, ca := testCert(t)
	f := newFake(t, &fakeServer{tls: tc, starttls: true, auth: true})
	env := map[string]string{"SMTP_USER": "packeteer", "SMTP_PASS": "correct horse"}
	y := "host: 127.0.0.1\nport: " + strconv.Itoa(f.port()) + "\nca_file: " + ca +
		"\nusername_env: SMTP_USER\npassword_env: SMTP_PASS\nfrom: packeteer@example.invalid\nto: [noc@example.invalid]\nsubject_prefix: ''"
	n, err := newNotifier(t, y, env)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.sawTLS {
		t.Fatal("mail was sent before STARTTLS")
	}
	raw, _ := base64.StdEncoding.DecodeString(f.authLine)
	if string(raw) != "\x00packeteer\x00correct horse" {
		t.Fatalf("auth %q", raw)
	}
	if hdr, _ := decodeBody(t, f.data); !strings.Contains(hdr, "Subject: [CRITICAL] bgp.session_down") {
		t.Fatalf("subject prefix not removed:\n%s", hdr)
	}
}

func TestImplicitTLS(t *testing.T) {
	tc, ca := testCert(t)
	f := newFake(t, &fakeServer{tls: tc, implicit: true})
	y := "host: 127.0.0.1\ntls: tls\nport: " + strconv.Itoa(f.port()) + "\nca_file: " + ca + "\nfrom: a@example.invalid\nto: [b@example.invalid]"
	n, err := newNotifier(t, y, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.sawTLS {
		t.Fatal("expected TLS")
	}
}

func TestStartTLSRequired(t *testing.T) {
	f := newFake(t, &fakeServer{})
	y := "host: 127.0.0.1\nport: " + strconv.Itoa(f.port()) + "\nfrom: a@example.invalid\nto: [b@example.invalid]"
	n, err := newNotifier(t, y, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = n.Notify(context.Background(), ev)
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err = %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.data != "" {
		t.Fatal("mail must not be sent in plaintext")
	}
}

func TestUntrustedCertFails(t *testing.T) {
	tc, _ := testCert(t)
	f := newFake(t, &fakeServer{tls: tc, starttls: true})
	y := "host: 127.0.0.1\nport: " + strconv.Itoa(f.port()) + "\nfrom: a@example.invalid\nto: [b@example.invalid]"
	n, err := newNotifier(t, y, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), ev); err == nil {
		t.Fatal("self-signed relay without ca_file must fail")
	}
}

func TestFilterSkipsDelivery(t *testing.T) {
	f := newFake(t, &fakeServer{})
	y := "host: 127.0.0.1\ntls: none\nport: " + strconv.Itoa(f.port()) + "\nfrom: a@example.invalid\nto: [b@example.invalid]\nevents: [\"commit.*\"]"
	n, err := newNotifier(t, y, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.delivered:
		t.Fatal("filtered event was mailed")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestConfigValidation(t *testing.T) {
	base := "from: a@example.invalid\nto: [b@example.invalid]\n"
	env := map[string]string{"U": "user", "P": "pass"}
	tests := []struct{ name, yaml, want string }{
		{"no host", base, "host is required"},
		{"bad tls", base + "host: h.example.invalid\ntls: ssl", `tls "ssl"`},
		{"bad port", base + "host: h.example.invalid\nport: 70000", "port"},
		{"half creds", base + "host: h.example.invalid\nusername_env: U", "both"},
		{"creds plaintext", base + "host: h.example.invalid\ntls: none\nusername_env: U\npassword_env: P", "require tls"},
		{"unset creds", base + "host: h.example.invalid\nusername_env: X\npassword_env: Y", "must be set"},
		{"bad from", "to: [b@example.invalid]\nhost: h.example.invalid\nfrom: nope", "from"},
		{"no to", "from: a@example.invalid\nhost: h.example.invalid", "to needs"},
		{"relative ca", base + "host: h.example.invalid\nca_file: ca.pem", "absolute"},
		{"ca without tls", base + "host: h.example.invalid\ntls: none\nca_file: /x.pem", "needs tls"},
		{"bad helo", base + "host: h.example.invalid\nhelo: 'a b'", "helo"},
		{"unknown key", base + "host: h.example.invalid\npassword: x", "field password not found"},
		{"bad events", base + "host: h.example.invalid\nevents: [x]", "matches no event kind"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newNotifier(t, tt.yaml, env)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
	n, err := newNotifier(t, base+"host: h.example.invalid\nusername_env: U\npassword_env: P", env)
	if err != nil {
		t.Fatal(err)
	}
	if s := n.(*Notifier); s.addr != "h.example.invalid:587" || s.mode != TLSStartTLS {
		t.Fatalf("defaults %+v", s)
	}
}
