package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/fieldreport"
)

// APITokenEnv is the API token `packeteer report` sends when the controller
// has sign-in on. The controller itself does not read it.
const APITokenEnv = "PACKETEER_API_TOKEN"

const (
	reportTimeout = 30 * time.Second
	reportMaxBody = 1 << 20
)

// reportClient never follows a redirect: Go would resend the credentials to
// the new location.
var reportClient = &http.Client{
	Timeout:       reportTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// runReport is `packeteer report --share`. It asks the running controller
// for the redacted summary, prints it, and writes the file only when the
// operator answers yes. It sends nothing anywhere else and never overwrites a
// file.
func runReport(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	defaultPath := DefaultConfigPath
	if p := getenv(ConfigEnv); p != "" {
		defaultPath = p
	}
	path := fs.String("config", defaultPath, "path to the YAML config file; http.listen tells where the controller is (env "+ConfigEnv+")")
	share := fs.Bool("share", false, "write a redacted summary to paste into an issue; every address, prefix, AS number, and host name becomes a documentation placeholder")
	base := fs.String("url", "", "base URL of the running controller (default: http.listen of the config); https, or http to a loopback address")
	out := fs.String("out", fieldreport.FileName, "file to write after you confirm; an existing file is never overwritten")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !*share {
		fmt.Fprintln(stderr, "usage: packeteer report --share [-config FILE] [-url URL] [-out FILE]")
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "packeteer: report: %v\n", err)
		return 1
	}
	if *base == "" {
		u, err := controllerURL(*path, getenv)
		if err != nil {
			return fail(err)
		}
		*base = u
	}
	text, err := fetchShare(ctx, *base, getenv)
	if err != nil {
		return fail(err)
	}
	fmt.Fprint(stdout, text)
	fmt.Fprintf(stdout, "\nThis is everything that would be written to %s. Nothing is sent anywhere.\nWrite %s? [y/N] ", *out, *out)
	answer, _ := bufio.NewReader(stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
		fmt.Fprintln(stdout, "\nNothing was written.")
		return 0
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fail(err)
	}
	if _, err := io.WriteString(f, text); err != nil {
		_ = f.Close()
		return fail(err)
	}
	if err := f.Close(); err != nil {
		return fail(err)
	}
	fmt.Fprintf(stdout, "Wrote %s. Read it once more, then paste it into the issue form.\n", *out)
	return 0
}

// controllerURL is the base URL of the controller the config describes.
func controllerURL(path string, getenv func(string) string) (string, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w (or give -url)", path, err)
	}
	if err := startConfig(cfg, getenv); err != nil {
		return "", err
	}
	listen := cfg.HTTPListen()
	if listen == "" {
		return "", errors.New("the config turns the HTTP server off (http.listen); the summary is read from it")
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("http.listen %q: %w", listen, err)
	}
	ip, perr := netip.ParseAddr(host)
	switch {
	case host == "" || perr == nil && ip.IsUnspecified():
		host = "127.0.0.1"
	case !config.LoopbackHost(host):
		return "", fmt.Errorf("http.listen %q is not a loopback address, so the credentials would cross the network in clear text: give -url with an https address", listen)
	}
	return "http://" + net.JoinHostPort(host, port), nil
}

// fetchShare reads GET /api/report/share. The credentials, the basic-auth
// account or the API token, go only to a loopback host or over https.
func fetchShare(ctx context.Context, base string, getenv func(string) string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || !config.SecureURL(u) {
		return "", errors.New("-url must be an https URL, or http to a loopback address, with no user info")
	}
	ctx, cancel := context.WithTimeout(ctx, reportTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/api/report/share", nil)
	if err != nil {
		return "", err
	}
	switch user, pass, tok := getenv(HTTPUserEnv), getenv(HTTPPassEnv), getenv(APITokenEnv); {
	case tok != "":
		req.Header.Set("Authorization", "Bearer "+tok)
	case user != "" && pass != "":
		req.SetBasicAuth(user, pass)
	}
	resp, err := reportClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("the controller at %s did not answer: %w", base, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("the controller refused the request (%d): set %s to an unscoped API token, or %s and %s", resp.StatusCode, APITokenEnv, HTTPUserEnv, HTTPPassEnv)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the controller answered %d", resp.StatusCode)
	}
	var body struct {
		Report string `json:"report"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, reportMaxBody)).Decode(&body); err != nil || body.Report == "" {
		return "", errors.New("the controller sent no report")
	}
	return body.Report, nil
}
