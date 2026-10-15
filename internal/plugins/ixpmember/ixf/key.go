package ixf

import (
	"errors"
	"hash/crc32"
	"net/url"
	"strings"
)

// APIKeyEnv is the IXP Manager API key. The header is the only place it
// is sent. The value is never written to the config file or the URL.
const APIKeyEnv = "PACKETEER_IXP_MANAGER_API_KEY"

// apiKeyHeader is IXP Manager's v7.3 header. The query form (?apikey=)
// is refused so the key cannot land in an access log.
const apiKeyHeader = "X-IXP-Manager-API-Key"

const (
	keyPrefix = "ixpm_"
	keyLen    = 56
	identLen  = 12
	secretLen = 32
	crcLen    = 6
)

const base62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// parseAPIKey checks a v7.3 key and returns its identifier.
// Legacy keys have no identifier; those are rejected so a log line cannot
// carry a slice of the secret. The error text never includes the key.
func parseAPIKey(key string) (string, error) {
	if len(key) != keyLen || !strings.HasPrefix(key, keyPrefix) {
		return "", errors.New("IXP Manager API key must be a v7.3 key (56 characters, ixpm_ prefix)")
	}
	payload := key[:keyLen-crcLen]
	sum := key[keyLen-crcLen:]
	got := crc32.ChecksumIEEE([]byte(payload))
	want, err := base62Decode(sum)
	if err != nil || got != uint32(want) {
		return "", errors.New("IXP Manager API key checksum does not match")
	}
	parts := strings.Split(payload, "_")
	if len(parts) != 3 || parts[0] != "ixpm" || len(parts[1]) != identLen || len(parts[2]) != secretLen ||
		!base62Only(parts[1]) || !base62Only(parts[2]) {
		return "", errors.New("IXP Manager API key must be a v7.3 key (12-character identifier, 32-character secret)")
	}
	return parts[1], nil
}

func base62Only(s string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(base62, s[i]) < 0 {
			return false
		}
	}
	return true
}

func base62Decode(s string) (uint64, error) {
	if len(s) != crcLen || !base62Only(s) {
		return 0, errors.New("bad checksum")
	}
	var n uint64
	for i := 0; i < len(s); i++ {
		n = n*62 + uint64(strings.IndexByte(base62, s[i]))
	}
	if n > 0xffffffff {
		return 0, errors.New("bad checksum")
	}
	return n, nil
}

// keySecret is the 32-character secret inside a v7.3-sized key.
// The checksum is not required: a mistyped key can still be the secret
// pasted into a URL. Empty when key does not have that shape.
func keySecret(key string) string {
	if len(key) != keyLen || !strings.HasPrefix(key, keyPrefix) {
		return ""
	}
	return key[len(keyPrefix)+identLen+1 : keyLen-crcLen]
}

// redact removes the key and its secret from a message. A redirect or a
// transport error can echo the request, and the secret must not be stored
// on the view.
func redact(msg, key string) string {
	if key == "" || msg == "" {
		return msg
	}
	ident := ""
	if id, err := parseAPIKey(key); err == nil {
		ident = id
	}
	msg = strings.ReplaceAll(msg, key, ident)
	if esc := url.QueryEscape(key); esc != key {
		msg = strings.ReplaceAll(msg, esc, ident)
	}
	if secret := keySecret(key); secret != "" {
		msg = strings.ReplaceAll(msg, secret, ident)
		if esc := url.QueryEscape(secret); esc != secret {
			msg = strings.ReplaceAll(msg, esc, ident)
		}
	}
	return msg
}
