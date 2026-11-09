// Command packeteer-policy is the reference consumer of the external policy
// feed (#232, docs/external-policy.md). It runs next to the operator's own
// BGP daemon, polls the feed, and either renders a template and runs a
// reload command (BIRD, OpenBGPD, any daemon with a config file) or speaks
// the ExaBGP process API on stdout. It drops every route when the feed's
// expiry passes, when the feed is off, and when it is stopped. It only
// reads the feed; Packeteer never connects to it.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/extpolicy"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("packeteer-policy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	feedURL := fs.String("url", "", "feed base URL, https://host:port (http only to a loopback host)")
	caFile := fs.String("ca-file", "", "PEM CA that signed the feed's certificate (default: system roots)")
	community := fs.String("community", "", "packeteer_community; a route without it is dropped (required)")
	allow := fs.String("allow", "", "comma-separated prefixes; a route outside them is dropped (default: any)")
	tokenEnv := fs.String("token-env", config.DefaultPolicyTokenEnv, "environment variable holding the bearer token")
	tmpl := fs.String("template", "", "render mode: Go text/template file")
	out := fs.String("out", "", "render mode: file to write")
	reload := fs.String("reload", "", "render mode: command run after each write, e.g. \"birdc configure\"")
	exa := fs.Bool("exabgp", false, "ExaBGP process mode: announce and withdraw lines on stdout")
	ver := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *ver {
		fmt.Fprintln(stderr, "packeteer-policy", version)
		return 0
	}
	if *feedURL == "" || *community == "" || *exa == (*tmpl != "") || (*tmpl != "") != (*out != "") {
		fmt.Fprintln(stderr, "packeteer-policy: need -url, -community, and either -exabgp or -template with -out")
		return 2
	}
	// The bearer token must not cross the network in clear.
	if u, err := url.Parse(*feedURL); err != nil || u.Host == "" || !config.SecureURL(u) {
		fmt.Fprintf(stderr, "packeteer-policy: -url %q must be https (http only to a loopback host)\n", *feedURL)
		return 2
	}
	check, err := parseCheck(*community, *allow)
	if err != nil {
		fmt.Fprintln(stderr, "packeteer-policy:", err)
		return 2
	}
	token := getenv(*tokenEnv)
	if token == "" {
		fmt.Fprintf(stderr, "packeteer-policy: %s is empty\n", *tokenEnv)
		return 2
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			fmt.Fprintln(stderr, "packeteer-policy:", err)
			return 1
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			fmt.Fprintf(stderr, "packeteer-policy: %s: no PEM certificates\n", *caFile)
			return 1
		}
		tlsCfg.RootCAs = pool
	}
	// Logs go to stderr: in ExaBGP mode stdout is the API.
	log := slog.New(slog.NewTextHandler(stderr, nil))
	var dst applier
	if *exa {
		dst = &exabgp{w: stdout}
	} else {
		r, err := newRenderer(*tmpl, *out, *reload)
		if err != nil {
			fmt.Fprintln(stderr, "packeteer-policy:", err)
			return 1
		}
		dst = r
	}
	// Each request also ends with its context: a heartbeat plus slack,
	// never past the expiry (consumer.step).
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     tlsCfg,
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			IdleConnTimeout:     90 * time.Second,
		},
		// The feed never redirects; following one could take the token
		// to another host or to http.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	c := &consumer{fetch: httpFetch(client, *feedURL, token), out: dst, check: check, log: log, now: time.Now}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("packeteer-policy starting", "version", version, "url", *feedURL)
	c.run(ctx)
	return 0
}

// parseCheck reads -community and -allow.
func parseCheck(community, allow string) (routeCheck, error) {
	text, err := config.CommunityText(community)
	if err != nil {
		return routeCheck{}, fmt.Errorf("-community %q: %w", community, err)
	}
	if text == extpolicy.NoExport {
		return routeCheck{}, errors.New("-community is packeteer_community, not NO_EXPORT")
	}
	rc := routeCheck{community: text}
	if allow == "" {
		return rc, nil
	}
	for _, s := range strings.Split(allow, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil || p != p.Masked() {
			return routeCheck{}, fmt.Errorf("-allow %q: want masked prefixes such as 198.51.100.0/24", s)
		}
		rc.allow = append(rc.allow, p)
	}
	return rc, nil
}
