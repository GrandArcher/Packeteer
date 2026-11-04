package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/twamp"
)

func TestVersionAndFlags(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"-version"}, &out, slog.New(slog.DiscardHandler)); err != nil || !strings.Contains(out.String(), "packeteer-reflector dev") {
		t.Fatalf("version: %v %q", err, out.String())
	}
	if err := run(context.Background(), []string{"-max-sessions", "0"}, &out, slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "must be positive") {
		t.Fatalf("max-sessions 0: %v", err)
	}
	if err := run(context.Background(), []string{"-listen", "nope"}, &out, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("bad listen accepted")
	}
	if err := run(context.Background(), []string{"-bogus"}, &out, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("unknown flag accepted")
	}
}

// The binary answers a sender on the port it was given and stops on
// cancel.
func TestReflects(t *testing.T) {
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-listen", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}, &bytes.Buffer{}, slog.New(slog.DiscardHandler))
	}()
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	pkt := twamp.SenderPacket{Seq: 3, Timestamp: time.Now(), ErrorEstimate: twamp.UnsyncedErrorEstimate, Padding: twamp.MinSenderPadding}.Marshal()
	buf := make([]byte, 1500)
	var n int
	for try := 0; try < 20; try++ {
		if _, err := c.Write(pkt); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if n, err = c.Read(buf); err == nil {
			break
		}
		// Before the port is bound the read fails at once with refused.
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("no reply: %v", err)
	}
	rp, err := twamp.ParseReflector(buf[:n])
	if err != nil || rp.SenderSeq != 3 {
		t.Fatalf("reply %+v, err %v", rp, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestParseAllow(t *testing.T) {
	got, err := parseAllow(" 192.0.2.0/24, 2001:db8::1 ,::ffff:198.51.100.7,::ffff:203.0.113.0/120")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::1/128"), netip.MustParsePrefix("198.51.100.7/32"), netip.MustParsePrefix("203.0.113.0/24")}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %v, want %v", i, got[i], want[i])
		}
	}
	if none, err := parseAllow(""); err != nil || len(none) != 0 {
		t.Errorf("empty list = %v, %v", none, err)
	}
	if _, err := parseAllow("192.0.2.0/24,nope"); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("bad entry: %v", err)
	}
	var out bytes.Buffer
	if err := run(context.Background(), []string{"-allow-from", "x"}, &out, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("run accepted a bad -allow-from")
	}
}

func TestListenAllWildcard(t *testing.T) {
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	conns, err := listenAll(":" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	if len(conns) < 1 || conns[0].LocalAddr().(*net.UDPAddr).IP.To4() == nil {
		t.Fatalf("conns %v", conns)
	}
	if len(conns) == 2 && conns[1].LocalAddr().(*net.UDPAddr).IP.To4() != nil {
		t.Fatalf("second socket is not IPv6: %v", conns[1].LocalAddr())
	}
}

// Port 0 gives the IPv4 and IPv6 sockets the same port.
func TestListenAllAnyPort(t *testing.T) {
	conns, err := listenAll(":0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	if len(conns) < 2 {
		t.Skip("no IPv6 socket here")
	}
	p4, p6 := conns[0].LocalAddr().(*net.UDPAddr).Port, conns[1].LocalAddr().(*net.UDPAddr).Port
	if p4 == 0 || p4 != p6 {
		t.Fatalf("ports %d and %d", p4, p6)
	}
}

func TestEveryFlagIsDocumented(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"-h"}, &out, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("-h returned no error")
	}
	doc, err := os.ReadFile("../../docs/reordering.md")
	if err != nil {
		t.Fatal(err)
	}
	flags := regexp.MustCompile(`(?m)^\s+-([a-z-]+)`).FindAllStringSubmatch(out.String(), -1)
	if len(flags) != 4 {
		t.Fatalf("usage lists %d flags, want 4:\n%s", len(flags), out.String())
	}
	for _, f := range flags {
		if !strings.Contains(string(doc), "| `-"+f[1]+"` |") {
			t.Errorf("docs/reordering.md has no table row for -%s", f[1])
		}
	}
}
