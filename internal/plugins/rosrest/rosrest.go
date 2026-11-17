// Package rosrest holds the RouterOS 7 REST API login that the mikrotik
// steerer (#300) and the routeros router check (#637) share. Each plugin
// builds its own client and decides which methods it sends.
package rosrest

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/plugins/exporter/sinkcfg"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Config is the RouterOS REST config block of the mikrotik steerer and the
// routeros router check. The REST API carries the router login, so the URL must be https (http only to a loopback host).
type Config struct {
	URL         string `yaml:"url"`
	UsernameEnv string `yaml:"username_env"`
	PasswordEnv string `yaml:"password_env"`
	// CAFile is an absolute path to the PEM certificate that signed the
	// router's REST certificate. Without it the system roots are used.
	CAFile string `yaml:"ca_file"`
}

// Login is a validated config: the API base (ending in /rest), the
// credentials, and a transport that trusts the router's certificate.
type Login struct {
	Base       string
	User, Pass string
	Transport  *http.Transport
}

// Login validates the config and reads the credentials. It contacts
// nothing. With env.CheckOnly unset variables are not an error.
func (c Config) Login(env plugin.Env) (Login, error) {
	u, err := sinkcfg.HTTPURL(c.URL)
	if err != nil {
		return Login{}, fmt.Errorf("url: %w", err)
	}
	if err := sinkcfg.TokenURL(u); err != nil {
		return Login{}, fmt.Errorf("url: %w", err)
	}
	if c.UsernameEnv == "" || c.PasswordEnv == "" {
		return Login{}, errors.New("username_env and password_env are required: the REST API needs a login")
	}
	user, pass, err := sinkcfg.Credentials(env.Getenv, c.UsernameEnv, c.PasswordEnv)
	if err != nil && !env.CheckOnly {
		return Login{}, err
	}
	tlsConf, err := sinkcfg.TLS(u.Scheme == "https", c.CAFile)
	if err != nil {
		return Login{}, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsConf
	return Login{Base: strings.TrimRight(u.String(), "/") + "/rest", User: user, Pass: pass, Transport: tr}, nil
}
