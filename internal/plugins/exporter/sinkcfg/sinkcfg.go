// Package sinkcfg holds the config checks the exporter plugins share:
// TLS to the sink, and credentials read from the environment.
package sinkcfg

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
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
	if user, err = secret(getenv, "username_env", userEnv); err != nil {
		return "", "", err
	}
	if pass, err = secret(getenv, "password_env", passEnv); err != nil {
		return "", "", err
	}
	return user, pass, nil
}

// secret reads one environment variable named by the config key field.
func secret(getenv func(string) string, field, name string) (string, error) {
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
