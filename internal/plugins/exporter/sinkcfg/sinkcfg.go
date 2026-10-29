// Package sinkcfg holds what the exporter plugins share: TLS to the sink,
// credentials read from the environment, and the HTTP endpoint checks and
// POST of the push exporters.
package sinkcfg

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
)

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// TLS returns the client TLS config for a sink. It is nil when tls is off.
// caFile is an absolute path to a PEM bundle for a private CA and needs
// tls on; the system roots are used when it is empty.
func TLS(on bool, caFile string) (*tls.Config, error) {
	if !on {
		if caFile != "" {
			return nil, fmt.Errorf("ca_file needs tls: true")
		}
		return nil, nil
	}
	conf := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile == "" {
		return conf, nil
	}
	if !filepath.IsAbs(caFile) {
		return nil, fmt.Errorf("ca_file must be an absolute path")
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ca_file: no PEM certificates")
	}
	conf.RootCAs = pool
	return conf, nil
}

// Credentials reads a username and password from the environment variables
// the config names. Both or neither: with neither it returns empty strings.
func Credentials(getenv func(string) string, userEnv, passEnv string) (user, pass string, err error) {
	if userEnv == "" && passEnv == "" {
		return "", "", nil
	}
	if userEnv == "" || passEnv == "" {
		return "", "", fmt.Errorf("username_env and password_env are set together")
	}
	if user, err = Secret(getenv, "username_env", userEnv); err != nil {
		return "", "", err
	}
	if pass, err = Secret(getenv, "password_env", passEnv); err != nil {
		return "", "", err
	}
	return user, pass, nil
}

// Secret reads one environment variable named by the config key field.
func Secret(getenv func(string) string, field, name string) (string, error) {
	if !envName.MatchString(name) {
		return "", fmt.Errorf("%s %q is not an environment variable name", field, name)
	}
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	v := getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s: %s is not set", field, name)
	}
	return v, nil
}

// HTTPURL parses a sink endpoint: an absolute http or https URL without
// credentials, query, or fragment.
func HTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("must be an absolute http(s) URL without credentials or query")
	}
	return u, nil
}

// Post sends body and treats any status outside 2xx as an error. The
// response body is drained but never reported, as it can echo the data.
func Post(ctx context.Context, client *http.Client, target string, header http.Header, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header = header.Clone()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("sink answered %s", resp.Status)
	}
	return nil
}
