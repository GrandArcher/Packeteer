package snmpcfg

import (
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestEnterpriseOID(t *testing.T) {
	if got, err := EnterpriseOID(""); err != nil || got != DefaultEnterpriseOID {
		t.Fatalf("default = %q, %v", got, err)
	}
	if got, err := EnterpriseOID(".1.3.6.1.4.1.32473.1"); err != nil || got != "1.3.6.1.4.1.32473.1" {
		t.Fatalf("leading dot = %q, %v", got, err)
	}
	for _, bad := range []string{"1.3.x", "2.5.1", "1..3", "1.3.01"} {
		if _, err := EnterpriseOID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestEngineID(t *testing.T) {
	if id, err := EngineID("0x8000000001"); err != nil || id != "\x80\x00\x00\x00\x01" {
		t.Fatalf("id = %q, %v", id, err)
	}
	for _, bad := range []string{"", "80", "zz00000001", strings.Repeat("00", 33)} {
		if _, err := EngineID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestUSMReadsTheEnvironmentAndKeepsLevelsApart(t *testing.T) {
	env := map[string]string{"U": "nms", "A": "auth-pass-123", "P": "priv-pass-456", "SHORT": "abc"}
	get := func(k string) string { return env[k] }
	usm, flags, err := V3{UsernameEnv: "U", AuthEnv: "A", PrivEnv: "P", AuthProtocol: "sha256", PrivProtocol: "AES256"}.USM(get)
	if err != nil {
		t.Fatal(err)
	}
	if flags != gosnmp.AuthPriv || usm.UserName != "nms" || usm.AuthenticationProtocol != gosnmp.SHA256 ||
		usm.PrivacyProtocol != gosnmp.AES256 || usm.AuthenticationPassphrase != "auth-pass-123" || usm.PrivacyPassphrase != "priv-pass-456" {
		t.Fatalf("usm = %+v flags %v", usm, flags)
	}
	if _, flags, err := (V3{UsernameEnv: "U", SecurityLevel: "noAuthNoPriv"}).USM(get); err != nil || flags != gosnmp.NoAuthNoPriv {
		t.Fatalf("noAuthNoPriv: %v %v", flags, err)
	}
	for name, v := range map[string]V3{
		"short passphrase": {UsernameEnv: "U", SecurityLevel: "authNoPriv", AuthEnv: "SHORT"},
		"auth on noAuth":   {UsernameEnv: "U", SecurityLevel: "noAuthNoPriv", AuthEnv: "A"},
		"priv on authNo":   {UsernameEnv: "U", SecurityLevel: "authNoPriv", AuthEnv: "A", PrivEnv: "P"},
		"unset user":       {UsernameEnv: "NOPE", AuthEnv: "A", PrivEnv: "P"},
		"bad level":        {UsernameEnv: "U", SecurityLevel: "max"},
	} {
		if _, _, err := v.USM(get); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	env["U"] = strings.Repeat("u", MaxUser+1)
	if _, _, err := (V3{UsernameEnv: "U", AuthEnv: "A", PrivEnv: "P"}).USM(get); err == nil {
		t.Error("a user name over 32 characters accepted")
	}
}

func TestSecretRefusesControlCharactersAndLongValues(t *testing.T) {
	env := map[string]string{
		"OK":   "lab-value-123",
		"LF":   "lab\nvalue-123",
		"CR":   "lab\rvalue-123",
		"NUL":  "lab\x00value-123",
		"LONG": strings.Repeat("x", MaxSecret+1),
		"EDGE": strings.Repeat("x", MaxSecret),
	}
	get := func(k string) string { return env[k] }
	for _, name := range []string{"OK", "EDGE"} {
		if _, err := Secret(get, "community_env", name, 1); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	for name, want := range map[string]string{"LF": "newline or NUL", "CR": "newline or NUL", "NUL": "newline or NUL", "LONG": "longer than"} {
		_, err := Secret(get, "community_env", name, 1)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", name, err, want)
		}
		if err != nil && strings.Contains(err.Error(), "value-123") {
			t.Errorf("%s: error leaks the value: %v", name, err)
		}
	}
	// The SNMPv3 passphrases go through the same check.
	if _, _, err := (V3{UsernameEnv: "OK", SecurityLevel: "authNoPriv", AuthEnv: "LF"}).USM(get); err == nil {
		t.Error("v3 passphrase with a newline accepted")
	}
}
