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
func classifyURL(raw, apiKey string) (string, bool, error) {
	if strings.TrimSpace(raw) == "" {
		return "", false, errors.New("url is required")
	}
	if apiKey != "" && strings.Contains(raw, apiKey) {
		return "", false, errors.New("url must not contain the API key")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return "", false, errors.New("url must be an http or https URL with a host and no userinfo or fragment")
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
