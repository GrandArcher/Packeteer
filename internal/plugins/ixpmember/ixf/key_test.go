package ixf

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// docKey is a v7.3-shaped vector. The checksum was computed with CRC-32/ISO-HDLC
// (the same sum IXP Manager uses) of the 50-byte payload, then base62.
// Identifier DocKeyIdent1, secret DocSecretDocSecretDocSecretDocSe.
const (
	docIdent  = "DocKeyIdent1"
	docSecret = "DocSecretDocSecretDocSecretDocSe"
	docKey    = "ixpm_DocKeyIdent1_DocSecretDocSecretDocSecretDocSe3DqwgX"
)

func TestParseAPIKey(t *testing.T) {
	id, err := parseAPIKey(docKey)
	if err != nil || id != docIdent {
		t.Fatalf("id %q err %v", id, err)
	}
	if strings.Contains(docKey, docSecret) && len(docKey) != 56 {
		t.Fatal("vector is not 56 characters")
	}
	flipped := docKey[:len(docKey)-1] + "Y"
	if _, err := parseAPIKey(flipped); err == nil || strings.Contains(err.Error(), docSecret) || strings.Contains(err.Error(), flipped) {
		t.Fatalf("flipped checksum: %v", err)
	}
	legacy := "LegacySecretLegacySecretLegacySecret12"
	if _, err := parseAPIKey(legacy); err == nil || strings.Contains(err.Error(), legacy) || strings.Contains(err.Error(), "LegacySecret") {
		t.Fatalf("legacy: %v", err)
	}
	short := docKey[:55]
	if _, err := parseAPIKey(short); err == nil || strings.Contains(err.Error(), docSecret) {
		t.Fatalf("short: %v", err)
	}
}

func TestKeyExpiryEvents(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		days int
		kind string
		left string
	}{
		{15, plugin.EventIXPKeyOK, "15"},
		{14, plugin.EventIXPKeyExpiring, "14"},
		{0, plugin.EventIXPKeyExpiring, "0"},
		{-3, plugin.EventIXPKeyExpiring, "-3"},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		log := slog.New(slog.NewTextHandler(&buf, nil))
		s := build(t, managerYAML(now.AddDate(0, 0, tc.days).Format("2006-01-02")), docKey, log)
		var got []plugin.Event
		s.SetEventSink(func(e plugin.Event) { got = append(got, e) })
		s.noteKey(now)
		s.noteKey(now)
		if len(got) != 1 || got[0].Kind != tc.kind {
			t.Fatalf("days %d events %+v", tc.days, got)
		}
		if got[0].Fields["identifier"] != docIdent || got[0].Fields["days_left"] != tc.left {
			t.Fatalf("days %d fields %v", tc.days, got[0].Fields)
		}
		text := buf.String() + got[0].Message
		if !strings.Contains(text, docIdent) || strings.Contains(text, docSecret) || strings.Contains(text, docKey) {
			t.Fatalf("days %d log %q", tc.days, text)
		}
	}
}

func TestKeyExpiryTransition(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	s := build(t, managerYAML(now.AddDate(0, 0, 15).Format("2006-01-02")), docKey, nil)
	var kinds []string
	s.SetEventSink(func(e plugin.Event) { kinds = append(kinds, e.Kind) })
	s.noteKey(now)
	s.noteKey(now.AddDate(0, 0, 1))
	if strings.Join(kinds, ",") != plugin.EventIXPKeyOK+","+plugin.EventIXPKeyExpiring {
		t.Fatalf("kinds %v", kinds)
	}
}

func TestKeyConfigRules(t *testing.T) {
	url := "https://ixp.example.invalid/api/v4/member-export/ixf/1.0"
	if err := newErr(t, "url: "+url+"\n", docKey); err == nil || !strings.Contains(err.Error(), "key_expires is required") {
		t.Fatalf("missing expiry: %v", err)
	}
	if err := newErr(t, "url: "+url+"\nkey_expires: \""+utcDay(10)+"\"\n", ""); err == nil || !strings.Contains(err.Error(), "key_expires is set") {
		t.Fatalf("expiry without key: %v", err)
	}
	if err := newErr(t, "url: "+url+"\nkey_expires: \""+utcDay(367)+"\"\n", docKey); err == nil || !strings.Contains(err.Error(), "366") {
		t.Fatalf("too far: %v", err)
	}
	for _, day := range []int{366, 0, -1} {
		if err := newErr(t, "url: "+url+"\nkey_expires: \""+utcDay(day)+"\"\n", docKey); err != nil {
			t.Fatalf("day %d: %v", day, err)
		}
	}
	if err := newErr(t, "url: "+url+"\nkey_expires: \""+utcDay(10)+"\"\nextra: true\n", docKey); err == nil || !strings.Contains(err.Error(), "field extra not found") {
		t.Fatalf("unknown field: %v", err)
	}
	quoted := build(t, "url: "+url+"\nkey_expires: \""+utcDay(20)+"\"\n", docKey, nil)
	bare := build(t, "url: "+url+"\nkey_expires: "+utcDay(20)+"\n", docKey, nil)
	stamp := time.Now().UTC().AddDate(0, 0, 20).Format(time.RFC3339)
	rfc := build(t, "url: "+url+"\nkey_expires: \""+stamp+"\"\n", docKey, nil)
	if quoted.expires.IsZero() || !quoted.expires.Equal(bare.expires) || !quoted.expires.Equal(rfc.expires) {
		t.Fatalf("expires quoted %s bare %s rfc %s", quoted.expires, bare.expires, rfc.expires)
	}
	if quoted.keyID != docIdent {
		t.Fatalf("key id %s", quoted.keyID)
	}
}

func TestRefreshBounds(t *testing.T) {
	base := "url: https://ixp.example.invalid/members.json\n"
	s := build(t, base, "", nil)
	if s.refresh != DefaultRefresh || s.http.Timeout != DefaultTimeout || s.maxBytes != DefaultMaxBytes {
		t.Fatalf("defaults refresh %s timeout %s bytes %d", s.refresh, s.http.Timeout, s.maxBytes)
	}
	if err := newErr(t, base+"refresh: 30s\n", ""); err == nil {
		t.Fatal("short refresh accepted")
	}
	if err := newErr(t, base+"refresh: 25h\n", ""); err == nil {
		t.Fatal("long refresh accepted")
	}
	if err := newErr(t, base+"timeout: 500ms\n", ""); err == nil {
		t.Fatal("short timeout accepted")
	}
	if err := newErr(t, base+"max_bytes: 512\n", ""); err == nil {
		t.Fatal("small max_bytes accepted")
	}
	ok := build(t, base+"refresh: 1m\ntimeout: 2m\nmax_bytes: 1024\n", "", nil)
	if ok.refresh != time.Minute || ok.http.Timeout != 2*time.Minute || ok.maxBytes != 1024 {
		t.Fatalf("bounds refresh %s timeout %s bytes %d", ok.refresh, ok.http.Timeout, ok.maxBytes)
	}
}

func managerYAML(day string) string {
	return "url: https://ixp.example.invalid/api/v4/member-export/ixf/1.0\nkey_expires: \"" + day + "\"\n"
}

func utcDay(n int) string {
	return time.Now().UTC().AddDate(0, 0, n).Format("2006-01-02")
}

func build(t *testing.T, yml, key string, log *slog.Logger) *Source {
	t.Helper()
	p, err := newPlugin(yml, key, log)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newErr(t *testing.T, yml, key string) error {
	t.Helper()
	_, err := newPlugin(yml, key, nil)
	return err
}

func newPlugin(yml, key string, log *slog.Logger) (*Source, error) {
	cfg, err := plugin.ConfigFromYAML(yml)
	if err != nil {
		return nil, err
	}
	p, err := New(cfg, plugin.Env{Logger: log, Getenv: func(k string) string {
		if k == APIKeyEnv {
			return key
		}
		return ""
	}})
	if err != nil {
		return nil, err
	}
	return p.(*Source), nil
}
