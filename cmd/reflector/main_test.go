package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
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
		done <- run(ctx, []string{"-listen", net.JoinHostPort("127.0.0.1", itoa(port))}, &bytes.Buffer{}, slog.New(slog.DiscardHandler))
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

func TestListenAllWildcard(t *testing.T) {
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	conns, err := listenAll(":" + itoa(port))
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

func itoa(n int) string { return strconv.Itoa(n) }
