package syslog

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func newNotifier(t *testing.T, y string) (*Notifier, error) {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	n, err := plugin.Notifiers.New(TypeName, c, plugin.Env{})
	if err != nil {
		return nil, err
	}
	return n.(*Notifier), nil
}

var ev = plugin.NewEvent(plugin.EventProviderDown, time.Date(2026, 1, 2, 3, 4, 5, 678000000, time.UTC),
	"probe source for transit-a is down", map[string]string{"provider": "transit-a", "reason": `no "route"]`})

// rfc5424 is the grammar of the header and structured data of RFC 5424.
var rfc5424 = regexp.MustCompile(`^<(\d{1,3})>1 (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,6}Z) ([\x21-\x7e]+) ([\x21-\x7e]{1,48}) (-|[\x21-\x7e]{1,128}) ([\x21-\x7e]{1,32}) ((?:\[[^\] ]+(?: [^\]= ]+="(?:[^"\\\]]|\\.)*")*\])+|-)(?: (.*))?$`)

func TestFormatIsRFC5424(t *testing.T) {
	n, err := newNotifier(t, "address: 192.0.2.1\nhostname: edge1.example.net")
	if err != nil {
		t.Fatal(err)
	}
	got := n.Format(ev)
	m := rfc5424.FindStringSubmatch(got)
	if m == nil {
		t.Fatalf("not RFC 5424: %q", got)
	}
	// local0 (16) * 8 + critical (2)
	if m[1] != "130" || m[2] != "2026-01-02T03:04:05.678000Z" || m[3] != "edge1.example.net" || m[4] != "packeteer" || m[5] != "-" || m[6] != "provider.down" {
		t.Errorf("header fields %q", m[1:7])
	}
	wantSD := `[packeteer@32473 kind="provider.down" severity="critical" dedup="packeteer/provider/provider=transit-a"]` +
		`[fields@32473 provider="transit-a" reason="no \"route\"\]"]`
	if m[7] != wantSD {
		t.Errorf("structured data\n got %s\nwant %s", m[7], wantSD)
	}
	if m[8] != "probe source for transit-a is down" {
		t.Errorf("msg %q", m[8])
	}
}

func TestSeverityMapsToSyslogPriority(t *testing.T) {
	n, err := newNotifier(t, "address: 192.0.2.1\nfacility: daemon")
	if err != nil {
		t.Fatal(err)
	}
	for sev, want := range map[plugin.Severity]string{plugin.SeverityInfo: "<30>", plugin.SeverityWarning: "<28>", plugin.SeverityCritical: "<26>"} {
		if got := n.Format(plugin.Event{Time: ev.Time, Kind: "x.y", Severity: sev}); !strings.HasPrefix(got, want+"1 ") {
			t.Errorf("%s: %q, want prefix %s", sev, got, want)
		}
	}
}

func TestEveryCatalogKindFormats(t *testing.T) {
	n, err := newNotifier(t, "address: 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range plugin.EventCatalog() {
		e := plugin.NewEvent(s.Kind, ev.Time, "m", map[string]string{"a": "b"})
		m := rfc5424.FindStringSubmatch(n.Format(e))
		if m == nil {
			t.Fatalf("%s is not RFC 5424: %q", s.Kind, n.Format(e))
		}
		if !strings.HasPrefix(s.Kind, m[6]) {
			t.Errorf("%s: msgid %q is not the kind cut to 32", s.Kind, m[6])
		}
	}
}

func TestFormatEscapesAndBounds(t *testing.T) {
	n, err := newNotifier(t, "address: 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	e := plugin.Event{Time: ev.Time, Kind: "outage.as", Severity: plugin.SeverityInfo,
		Message: "line1\nline2 \u00e9 " + strings.Repeat("x", 5000),
		Fields:  map[string]string{"bad key=]\"": "v", "long": strings.Repeat("y", 2000)}}
	got := n.Format(e)
	if len(got) > maxDatagram {
		t.Errorf("UDP message is %d bytes, over %d", len(got), maxDatagram)
	}
	if strings.ContainsAny(got, "\n\r") {
		t.Error("a newline survived")
	}
	m := rfc5424.FindStringSubmatch(got)
	if m == nil {
		t.Fatalf("not RFC 5424: %.300q", got)
	}
	if !strings.Contains(m[7], `bad_key___="v"`) {
		t.Errorf("parameter name not sanitized: %s", m[7][:min(len(m[7]), 300)])
	}
	if !strings.HasPrefix(m[8], "\xef\xbb\xbfline1 line2 \u00e9 x") {
		t.Errorf("a UTF-8 message needs the BOM: %.40q", m[8])
	}
	if !strings.Contains(m[7], `long="`+strings.Repeat("y", maxSDValue)+`"`) {
		t.Error("a structured data value is cut to maxSDValue")
	}
}

func TestUDP(t *testing.T) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	n, err := newNotifier(t, "address: 127.0.0.1\nport: "+strconv.Itoa(c.LocalAddr().(*net.UDPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	k, _, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:k]) != n.Format(ev) {
		t.Fatalf("datagram %q", buf[:k])
	}
}

// readFrames reads octet-counted frames (RFC 6587 section 3.4.1).
func readFrames(t *testing.T, r io.Reader, out chan<- string) {
	t.Helper()
	br := bufio.NewReader(r)
	for {
		lenStr, err := br.ReadString(' ')
		if err != nil {
			return
		}
		size, err := strconv.Atoi(strings.TrimSuffix(lenStr, " "))
		if err != nil {
			t.Errorf("bad frame length %q", lenStr)
			return
		}
		msg := make([]byte, size)
		if _, err := io.ReadFull(br, msg); err != nil {
			return
		}
		out <- string(msg)
	}
}

func TestTCPFramesAndReconnects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conns := make(chan net.Conn, 4)
	frames := make(chan string, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns <- c
			go readFrames(t, c, frames)
		}
	}()
	n, err := newNotifier(t, "address: 127.0.0.1\ntransport: tcp\nport: "+strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	defer n.Stop(context.Background())
	for i := 0; i < 2; i++ {
		if err := n.Notify(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
		if got := <-frames; got != n.Format(ev) {
			t.Fatalf("frame %q", got)
		}
		if i == 0 {
			(<-conns).Close() // the collector restarts
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// selfSigned writes a CA-and-server certificate for name and returns the
// certificate to serve and the PEM file a client trusts.
func selfSigned(t *testing.T, name string) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, path
}

func TestTLSVerifiesTheCollector(t *testing.T) {
	cert, ca := selfSigned(t, "localhost")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	frames := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go readFrames(t, c, frames)
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	n, err := newNotifier(t, "address: localhost\ntransport: tls\nport: "+port+"\nca_file: "+ca)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Stop(context.Background())
	if err := n.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if got := <-frames; got != n.Format(ev) {
		t.Fatalf("frame %q", got)
	}

	// Without the CA the collector's certificate is not trusted.
	bad, err := newNotifier(t, "address: localhost\ntransport: tls\nport: "+port)
	if err != nil {
		t.Fatal(err)
	}
	if err := bad.Notify(context.Background(), ev); err == nil {
		t.Fatal("an untrusted collector certificate must fail the delivery")
	}
}

func TestFilteredEventIsNotSent(t *testing.T) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	n, err := newNotifier(t, "address: 127.0.0.1\nport: "+strconv.Itoa(c.LocalAddr().(*net.UDPAddr).Port)+"\nevents: [\"bgp.*\"]")
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := c.ReadFromUDP(make([]byte, 1500)); err == nil {
		t.Fatal("filtered event was sent")
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct{ name, yaml, want string }{
		{"no address", "port: 514", "address is required"},
		{"bad address", "address: 'a b'", "hostname or IP"},
		{"bad port", "address: 192.0.2.1\nport: 70000", "port"},
		{"bad transport", "address: 192.0.2.1\ntransport: sctp", "transport"},
		{"bad facility", "address: 192.0.2.1\nfacility: kern", "facility"},
		{"bad app", "address: 192.0.2.1\napp_name: 'my app'", "app_name"},
		{"bad host", "address: 192.0.2.1\nhostname: 'my host'", "hostname"},
		{"ca without tls", "address: 192.0.2.1\nca_file: /etc/ca.pem", "needs tls"},
		{"relative ca", "address: 192.0.2.1\ntransport: tls\nca_file: ca.pem", "absolute"},
		{"timeout", "address: 192.0.2.1\ntimeout: 2m", "timeout"},
		{"unknown key", "address: 192.0.2.1\npassword: x", "field password not found"},
		{"bad filter", "address: 192.0.2.1\nmin_severity: loud", "min_severity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newNotifier(t, tt.yaml)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
	for _, ok := range []string{
		"address: 192.0.2.1",
		"address: 2001:db8::1\ntransport: tcp",
		"address: logs.example.net\ntransport: tls\nfacility: local7",
	} {
		if _, err := newNotifier(t, ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	if n, _ := newNotifier(t, "address: logs.example.net\ntransport: tls"); n.addr != "logs.example.net:6514" {
		t.Errorf("tls default port: %s", n.addr)
	}
}
