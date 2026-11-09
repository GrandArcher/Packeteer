// Package outbound holds the rules for what Packeteer sends to other hosts:
// which environment variables a config value may expand, and which
// redirects an HTTP client follows (#489).
package outbound

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// maxRedirects bounds one redirect chain.
const maxRedirects = 3

// Expand replaces ${VAR} and $VAR in s from getenv. Only names that start
// with prefix expand; any other name, or an unset one, is an error. The
// config editor can set a webhook or collector URL, so a free expansion
// would let it send any secret in the environment (the admin password, a
// registry key) to a host it chose.
func Expand(s, prefix string, getenv func(string) string) (string, error) {
	var refused, missing string
	out := os.Expand(s, func(name string) string {
		if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) {
			if refused == "" {
				refused = name
			}
			return ""
		}
		v := ""
		if getenv != nil {
			v = getenv(name)
		}
		if v == "" && missing == "" {
			missing = name
		}
		return v
	})
	switch {
	case refused != "":
		return "", fmt.Errorf("${%s} is not allowed: only %s* variables expand here", refused, prefix)
	case missing != "":
		return "", fmt.Errorf("%s is not set", missing)
	}
	return out, nil
}

var errTooMany = fmt.Errorf("stopped after %d redirects", maxRedirects)

// sameHost reports whether to is on the host and port of from, with the
// same scheme or an upgrade from http to https.
func sameHost(to, from *url.URL) bool {
	if !strings.EqualFold(to.Hostname(), from.Hostname()) || to.Port() != from.Port() {
		return false
	}
	return to.Scheme == from.Scheme || (from.Scheme == "http" && to.Scheme == "https")
}

// SameHost is an http.Client CheckRedirect. It follows a redirect only on
// the host of the first request, so a custom header (a token) never
// reaches another host and a server cannot point the client elsewhere.
func SameHost(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errTooMany
	}
	if !sameHost(req.URL, via[0].URL) {
		return fmt.Errorf("refusing a redirect to another host (%s)", req.URL.Host)
	}
	return nil
}

// AnyHTTPSHost is an http.Client CheckRedirect for a bootstrap service
// that sends each query on to the server that holds the answer (rdap.org
// to a registry's RDAP server). It also follows an https redirect to
// another host, and then sends only the Accept header.
func AnyHTTPSHost(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errTooMany
	}
	if sameHost(req.URL, via[0].URL) {
		return nil
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing a redirect to %s on another host", req.URL.Scheme)
	}
	accept := req.Header.Get("Accept")
	req.Header = http.Header{}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	return nil
}
