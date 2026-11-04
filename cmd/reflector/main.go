// Command packeteer-reflector is a TWAMP-Light Session-Reflector (RFC 5357,
// unauthenticated mode) for Packeteer's reordering measurement (#224). Run
// it on a host you control that is reachable through every provider, and
// list that host under probe.reorder.responders. It answers any
// TWAMP-Light sender, so a standard sender can test the path too.
//
//	packeteer-reflector [-listen :862] [-max-sessions 1024] [-allow-from 192.0.2.0/24,2001:db8::/32]
//
// It reads nothing but test packets, sends only replies, and never speaks
// BGP. It is a separate binary so a probe responder never carries the
// controller's config or credentials.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/GrandArcher/Packeteer/internal/twamp"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, slog.New(slog.NewTextHandler(os.Stderr, nil))); err != nil {
		fmt.Fprintln(os.Stderr, "packeteer-reflector:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer, log *slog.Logger) error {
	fs := flag.NewFlagSet("packeteer-reflector", flag.ContinueOnError)
	fs.SetOutput(out)
	listen := fs.String("listen", ":"+strconv.Itoa(twamp.DefaultPort), "UDP address to answer on; an empty host answers on IPv4 and IPv6")
	maxSessions := fs.Int("max-sessions", twamp.DefaultMaxSessions, "senders (address and port) that keep a sequence counter")
	allowFrom := fs.String("allow-from", "", "comma-separated addresses or prefixes that may use the reflector; empty answers any sender")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Fprintln(out, "packeteer-reflector", version)
		return nil
	}
	if *maxSessions < 1 {
		return fmt.Errorf("-max-sessions %d must be positive", *maxSessions)
	}
	allow, err := parseAllow(*allowFrom)
	if err != nil {
		return err
	}
	conns, err := listenAll(*listen)
	if err != nil {
		return err
	}
	r := twamp.NewReflector(*maxSessions)
	r.AllowFrom(allow)
	if len(allow) == 0 {
		log.Warn("answering any sender; set -allow-from so the host cannot be used to reflect traffic at spoofed addresses")
	}
	errs := make(chan error, len(conns))
	for _, c := range conns {
		log.Info("reflecting", "listen", c.LocalAddr().String(), "version", version)
		go func(c *net.UDPConn) { errs <- twamp.Serve(ctx, c, r, log) }(c)
	}
	var first error
	for range conns {
		if err := <-errs; err != nil && first == nil {
			first = err
		}
	}
	return first
}

// parseAllow reads the -allow-from list: addresses or prefixes, separated
// by commas.
func parseAllow(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(list, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			a, aerr := netip.ParseAddr(f)
			if aerr != nil {
				return nil, fmt.Errorf("-allow-from %q is not an address or prefix", f)
			}
			p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// listenAll opens the listen address. A wildcard host gets one IPv4 and
// one IPv6 socket, so each reply carries the sender's TTL from its own
// family; a host without IPv6 just gets the IPv4 one.
func listenAll(addr string) ([]*net.UDPConn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("-listen %q: %w", addr, err)
	}
	if host != "" {
		a, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("-listen %q: %w", addr, err)
		}
		network := "udp4"
		if a.IP.To4() == nil {
			network = "udp6"
		}
		c, err := net.ListenUDP(network, a)
		if err != nil {
			return nil, err
		}
		return []*net.UDPConn{c}, nil
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("-listen %q: %w", addr, err)
	}
	c4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: p})
	if err != nil {
		return nil, err
	}
	conns := []*net.UDPConn{c4}
	// Port 0 picks one port, so both families answer on the same one.
	p = c4.LocalAddr().(*net.UDPAddr).Port
	c6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: p})
	if err == nil {
		conns = append(conns, c6)
	} else if !errors.Is(err, syscall.EAFNOSUPPORT) && !errors.Is(err, syscall.EADDRNOTAVAIL) {
		_ = c4.Close()
		return nil, err
	}
	return conns, nil
}
