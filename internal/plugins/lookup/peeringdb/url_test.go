package peeringdb

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestParseKey(t *testing.T) {
	if k, err := parseKey("  "); err != nil || k != "" {
		t.Fatalf("blank: %q %v", k, err)
	}
	if k, err := parseKey(" " + docKey + "\n"); err != nil || k != docKey {
		t.Fatalf("trimmed: %q %v", k, err)
	}
	for _, bad := range []string{"a b", "a\tb", "a\x00b", "k\u00e9y", strings.Repeat("k", maxKeyLen+1)} {
		if _, err := parseKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseBaseDefaultsAndTrims(t *testing.T) {
	u, err := parseBase("", "")
	if err != nil || u.String() != DefaultBaseURL {
		t.Fatalf("default %v %v", u, err)
	}
	u, err = parseBase("https://pdb.example.invalid/prefix/", docKey)
	if err != nil || u.String() != "https://pdb.example.invalid/prefix" {
		t.Fatalf("trim %v %v", u, err)
	}
}

func TestURLHasKeyFindsEncodedForms(t *testing.T) {
	enc := "%" + strings.ToUpper(string("0123456789abcdef"[docKey[0]>>4])) + strings.ToUpper(string("0123456789abcdef"[docKey[0]&15]))
	for _, raw := range []string{
		"https://" + docKey + ".example.invalid/",
		"https://x.example.invalid/" + docKey,
		"https://x.example.invalid/" + enc + docKey[1:],
		"https://x.example.invalid/?k=" + docKey,
		"https://x.example.invalid/?k=" + enc + docKey[1:],
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !urlHasKey(raw, u, docKey) {
			t.Errorf("missed key in %s", raw)
		}
	}
	u, _ := url.Parse("https://x.example.invalid/members.json")
	if urlHasKey("https://x.example.invalid/members.json", u, docKey) || urlHasKey("x", u, "") {
		t.Fatal("false positive")
	}
}

func TestParseIXFURL(t *testing.T) {
	if got, err := parseIXFURL("  ", docKey); err != nil || got != "" {
		t.Fatalf("blank %q %v", got, err)
	}
	if got, err := parseIXFURL("http://ixf.example.invalid/m.json", ""); err != nil || got != "http://ixf.example.invalid/m.json" {
		t.Fatalf("plain http %q %v", got, err)
	}
	long := "https://ixf.example.invalid/" + strings.Repeat("a", maxURLLen)
	if _, err := parseIXFURL(long, ""); err == nil {
		t.Fatal("over-long URL accepted")
	}
}

func TestRedact(t *testing.T) {
	key := "a b&c"
	msg := "got " + key + " and " + url.QueryEscape(key) + " and " + url.PathEscape(key)
	got := redact(msg, key)
	if strings.Contains(got, "a b") || strings.Contains(got, "a+b") || strings.Contains(got, "a%20b") {
		t.Fatalf("redact left the key: %q", got)
	}
	if redact("plain", "") != "plain" {
		t.Fatal("empty key changed the message")
	}
}

func TestAuthorizeOnlyOnConfiguredBase(t *testing.T) {
	s := newSource(t, "base_url: https://pdb.example.invalid\nexchanges:\n  - {name: a, ix_id: 1}\n", docKey)
	for raw, want := range map[string]string{
		"https://pdb.example.invalid/api/ix":  "Api-Key " + docKey,
		"https://PDB.example.invalid/api/ix":  "Api-Key " + docKey,
		"https://other.example.invalid/x":     "",
		"http://pdb.example.invalid/api/ix":   "",
		"https://pdb.example.invalid:8443/ix": "",
	} {
		req, _ := http.NewRequest(http.MethodGet, raw, nil)
		s.authorize(req)
		if got := req.Header.Get("Authorization"); got != want {
			t.Errorf("%s: Authorization %q, want %q", raw, got, want)
		}
	}
}
