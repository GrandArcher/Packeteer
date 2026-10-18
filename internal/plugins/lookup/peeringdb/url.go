package peeringdb

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// parseKey accepts an empty key (anonymous) or a single token. PeeringDB
// publishes no key grammar; the checks only reject values that cannot be
// a header token or that would need encoding.
func parseKey(raw string) (string, error) {
	k := strings.TrimSpace(raw)
	if k == "" {
		return "", nil
	}
	if len(k) > maxKeyLen {
		return "", errors.New("API key is too long")
	}
	for _, r := range k {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) || unicode.IsSpace(r) {
			return "", errors.New("API key has an invalid character")
		}
	}
	return k, nil
}

func parseBase(raw, key string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		raw = DefaultBaseURL
	}
	u, err := parseHTTPURL(raw, "base_url")
	if err != nil {
		return nil, err
	}
	if key != "" && u.Scheme != "https" {
		return nil, errors.New("base_url must be https when an API key is set")
	}
	if urlHasKey(raw, u, key) {
		return nil, errors.New("base_url must not contain the API key")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u, nil
}

func parseIXFURL(raw, key string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	u, err := parseHTTPURL(raw, "ixf_url")
	if err != nil {
		return "", err
	}
	if urlHasKey(raw, u, key) {
		return "", errors.New("ixf_url must not contain the API key")
	}
	if len(raw) > maxURLLen {
		return "", fmt.Errorf("ixf_url longer than %d bytes", maxURLLen)
	}
	return raw, nil
}

func parseHTTPURL(raw, what string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New(what + " must be an http or https URL with a host and no userinfo, query, or fragment")
	}
	if len(raw) > maxURLLen {
		return nil, fmt.Errorf("%s longer than %d bytes", what, maxURLLen)
	}
	return u, nil
}

// urlHasKey reports whether key appears in raw or in the percent-decoded
// URL. A check of the raw string alone misses a key whose first character
// was percent-encoded.
func urlHasKey(raw string, u *url.URL, key string) bool {
	if key == "" || u == nil {
		return false
	}
	if strings.Contains(raw, key) || strings.Contains(u.String(), key) || strings.Contains(u.Host, key) || strings.Contains(u.Path, key) || strings.Contains(u.RawPath, key) {
		return true
	}
	if dec, err := url.PathUnescape(raw); err == nil && strings.Contains(dec, key) {
		return true
	}
	if dec, err := url.QueryUnescape(raw); err == nil && strings.Contains(dec, key) {
		return true
	}
	for k, vals := range u.Query() {
		if strings.Contains(k, key) {
			return true
		}
		for _, v := range vals {
			if strings.Contains(v, key) {
				return true
			}
		}
	}
	return false
}

func redact(msg, key string) string {
	if key == "" || msg == "" {
		return msg
	}
	msg = strings.ReplaceAll(msg, key, "redacted")
	if esc := url.QueryEscape(key); esc != key {
		msg = strings.ReplaceAll(msg, esc, "redacted")
	}
	if esc := url.PathEscape(key); esc != key {
		msg = strings.ReplaceAll(msg, esc, "redacted")
	}
	return msg
}

// validName matches the exchange name rule used in config, so the same
// label can name an exchange in both places. The config package is not
// imported from a plugin.
func validName(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i, r := range s {
		letter := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		digit := r >= '0' && r <= '9'
		if i == 0 {
			if !letter && !digit {
				return false
			}
			continue
		}
		if !letter && !digit && r != '_' && r != '.' && r != '-' {
			return false
		}
	}
	return true
}
