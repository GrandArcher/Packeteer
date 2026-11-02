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
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("packeteer-policy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	url := fs.String("url", "", "feed base URL, https://host:port")
	caFile := fs.String("ca-file", "", "PEM CA that signed the feed's certificate (default: system roots)")
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
	if *url == "" || *exa == (*tmpl != "") || (*tmpl != "") != (*out != "") {
		fmt.Fprintln(stderr, "packeteer-policy: need -url and either -exabgp or -template with -out")
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
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	c := &consumer{fetch: httpFetch(client, *url, token), out: dst, log: log, now: time.Now}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("packeteer-policy starting", "version", version, "url", *url)
	c.run(ctx)
	return 0
}
