// Package snmpcfg holds what the snmptrap notifier and the snmpagent
// exporter share: the enterprise OID, and SNMPv3 credentials read from the
// environment.
package snmpcfg

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// DefaultEnterpriseOID is NET-SNMP's netSnmpPlaypen arc, set aside for
// local experiments. Packeteer has no enterprise number; set
// enterprise_oid to your own arc for production receivers.
const DefaultEnterpriseOID = "1.3.6.1.4.1.8072.9999.9999.7717"

const (
	// minPassphrase is the shortest USM passphrase (RFC 3414 section 11.2).
	minPassphrase = 8
	// maxUser is the longest USM user name (RFC 3414).
	maxUser = 32
)

var (
	envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	oidRe   = regexp.MustCompile(`^1(\.(0|[1-9][0-9]{0,9}))+$`)
)

// EnterpriseOID checks a configured base OID. Empty is the default.
func EnterpriseOID(s string) (string, error) {
	if s == "" {
		return DefaultEnterpriseOID, nil
	}
	base := strings.TrimPrefix(s, ".")
	if !oidRe.MatchString(base) {
		return "", fmt.Errorf("enterprise_oid %q is not a numeric OID", s)
	}
	return base, nil
}

// EngineID decodes a configured SNMP engine ID: 5 to 32 bytes of hex,
// with an optional 0x prefix.
func EngineID(s string) (string, error) {
	id, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(s), "0x"))
	if err != nil || len(id) < 5 || len(id) > 32 {
		return "", fmt.Errorf("engine_id must be 5 to 32 bytes of hex")
	}
	return string(id), nil
}

// Secret reads the environment variable the config key names. A value
// shorter than minLen is refused.
func Secret(getenv func(string) string, key, name string, minLen int) (string, error) {
	if !envName.MatchString(name) {
		return "", fmt.Errorf("%s is required and must be an environment variable name", key)
	}
	v := getenv(name)
	if len(v) < minLen {
		if v == "" {
			return "", fmt.Errorf("%s: %s is not set", key, name)
		}
		return "", fmt.Errorf("%s: %s must be at least %d characters", key, name, minLen)
	}
	return v, nil
}

// V3 is the SNMPv3 user keys of a config block.
type V3 struct {
	UsernameEnv   string
	SecurityLevel string
	AuthProtocol  string
	AuthEnv       string
	PrivProtocol  string
	PrivEnv       string
}

// USM validates the keys and reads the user and passphrases. The security
// level defaults to authPriv.
func (v V3) USM(getenv func(string) string) (*gosnmp.UsmSecurityParameters, gosnmp.SnmpV3MsgFlags, error) {
	usm := &gosnmp.UsmSecurityParameters{AuthenticationProtocol: gosnmp.NoAuth, PrivacyProtocol: gosnmp.NoPriv}
	var err error
	if usm.UserName, err = Secret(getenv, "username_env", v.UsernameEnv, 1); err != nil {
		return nil, 0, err
	}
	if len(usm.UserName) > maxUser {
		return nil, 0, fmt.Errorf("username_env: longer than %d characters", maxUser)
	}
	level := v.SecurityLevel
	if level == "" {
		level = "authPriv"
	}
	var flags gosnmp.SnmpV3MsgFlags
	switch level {
	case "noAuthNoPriv":
		flags = gosnmp.NoAuthNoPriv
	case "authNoPriv":
		flags = gosnmp.AuthNoPriv
	case "authPriv":
		flags = gosnmp.AuthPriv
	default:
		return nil, 0, fmt.Errorf("security_level %q is invalid (want noAuthNoPriv, authNoPriv, authPriv)", v.SecurityLevel)
	}
	if flags == gosnmp.NoAuthNoPriv && (v.AuthProtocol != "" || v.AuthEnv != "") {
		return nil, 0, fmt.Errorf("security_level noAuthNoPriv does not use auth")
	}
	if flags != gosnmp.AuthPriv && (v.PrivProtocol != "" || v.PrivEnv != "") {
		return nil, 0, fmt.Errorf("security_level %s does not use privacy", level)
	}
	if flags != gosnmp.NoAuthNoPriv {
		if usm.AuthenticationProtocol, err = authProto(v.AuthProtocol); err != nil {
			return nil, 0, err
		}
		if usm.AuthenticationPassphrase, err = Secret(getenv, "auth_env", v.AuthEnv, minPassphrase); err != nil {
			return nil, 0, err
		}
	}
	if flags == gosnmp.AuthPriv {
		if usm.PrivacyProtocol, err = privProto(v.PrivProtocol); err != nil {
			return nil, 0, err
		}
		if usm.PrivacyPassphrase, err = Secret(getenv, "priv_env", v.PrivEnv, minPassphrase); err != nil {
			return nil, 0, err
		}
	}
	return usm, flags, nil
}

func authProto(s string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch strings.ToUpper(s) {
	case "", "SHA":
		return gosnmp.SHA, nil
	case "SHA224":
		return gosnmp.SHA224, nil
	case "SHA256":
		return gosnmp.SHA256, nil
	case "SHA384":
		return gosnmp.SHA384, nil
	case "SHA512":
		return gosnmp.SHA512, nil
	case "MD5":
		return gosnmp.MD5, nil
	}
	return 0, fmt.Errorf("auth_protocol %q is invalid (want SHA, SHA224, SHA256, SHA384, SHA512, MD5)", s)
}

func privProto(s string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch strings.ToUpper(s) {
	case "", "AES":
		return gosnmp.AES, nil
	case "AES192":
		return gosnmp.AES192, nil
	case "AES256":
		return gosnmp.AES256, nil
	case "AES192C":
		return gosnmp.AES192C, nil
	case "AES256C":
		return gosnmp.AES256C, nil
	case "DES":
		return gosnmp.DES, nil
	}
	return 0, fmt.Errorf("priv_protocol %q is invalid (want AES, AES192, AES256, AES192C, AES256C, DES)", s)
}
