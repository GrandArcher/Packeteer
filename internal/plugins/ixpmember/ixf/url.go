package ixf

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// secretQuery is never sent, on the manager URL or on a named document.
// The error names the query key and not its value.
var secretQuery = map[string]bool{
	"apikey": true, "api_key": true, "access_key": true,
	"key": true, "token": true, "password": true,
}

// classifyURL decides whether url is the IXP Manager member export or one
// named IX-F document. The API key is sent only to the manager export.
// An empty path, or a path that ends with the export path (a subdirectory
// install), is the manager. Anything else is fetched exactly, with no key.
// A key on a URL that is not the manager export is an error here.
func classifyURL(raw, apiKey string) (string, bool, error) {
	if strings.TrimSpace(raw) == "" {
		return "", false, errors.New("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return "", false, errors.New("url must be an http or https URL with a host and no userinfo or fragment")
	}
	// Reject before the URL is copied into fetchURL. Percent-encoding the
	// first character hides the key from a raw substring check, and
	// EscapedPath keeps that encoding, so the secret would stay on the
	// request line and on GET /api/ixp/members.
	if urlHasKey(raw, u, apiKey) {
		return "", false, errors.New("url must not contain the API key")
	}
	q := u.Query()
	for k := range q {
		if secretQuery[strings.ToLower(k)] {
			return "", false, fmt.Errorf("url query %q is not allowed", k)
		}
	}
	path := strings.TrimRight(u.Path, "/")
	if managerPath(path) {
		if err := allowManagerQuery(q); err != nil {
			return "", false, err
		}
		if path == "" {
			u.Path = exportPath
		} else {
			u.Path = path
		}
		u.RawQuery = q.Encode()
		u.Fragment = ""
		return u.String(), true, nil
	}
	if apiKey != "" {
		return "", false, errors.New("API key is only sent to the IXP Manager member export")
	}
	return raw, false, nil
}

// urlHasKey reports whether the API key or its secret appears in raw or
// in the decoded URL. url.Parse decodes the path but String keeps the
// original percent-encoding, so both forms are checked.
func urlHasKey(raw string, u *url.URL, apiKey string) bool {
	if apiKey == "" {
		return false
	}
	if keyIn(raw, apiKey) || keyIn(u.Path, apiKey) || keyIn(u.Host, apiKey) || keyIn(u.RawPath, apiKey) || keyIn(u.String(), apiKey) {
		return true
	}
	if dec, err := url.PathUnescape(raw); err == nil && keyIn(dec, apiKey) {
		return true
	}
	if dec, err := url.PathUnescape(u.Host); err == nil && keyIn(dec, apiKey) {
		return true
	}
	for k, vals := range u.Query() {
		if keyIn(k, apiKey) {
			return true
		}
		for _, v := range vals {
			if keyIn(v, apiKey) {
				return true
			}
		}
	}
	return false
}

func keyIn(s, apiKey string) bool {
	if s == "" || apiKey == "" {
		return false
	}
	if strings.Contains(s, apiKey) {
		return true
	}
	secret := keySecret(apiKey)
	return secret != "" && strings.Contains(s, secret)
}

func managerPath(path string) bool {
	if path == "" {
		return true
	}
	return path == exportPath || strings.HasSuffix(path, exportPath)
}

func allowManagerQuery(q url.Values) error {
	for k, vals := range q {
		if len(vals) != 1 || !managerQueryOK(k, vals[0]) {
			return fmt.Errorf("url query %q is not allowed", k)
		}
	}
	return nil
}

func managerQueryOK(k, v string) bool {
	if k == "ignore_missing_ixfid" && v == "1" {
		return true
	}
	id, ok := strings.CutPrefix(k, "ixfid_")
	return ok && digits(id) && digits(v)
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
