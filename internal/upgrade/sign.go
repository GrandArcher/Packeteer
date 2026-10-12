package upgrade

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// A release publishes SHA256SUMS and SHA256SUMS.sig: a base64 Ed25519
// signature over the exact bytes of SHA256SUMS. cmd/relsign makes both.

// GenerateKey makes a signing key pair, base64 encoded.
func GenerateKey() (public, private string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv), nil
}

// Sign returns the base64 signature of msg under a base64 private key.
func Sign(private string, msg []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(private))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return "", errors.New("private key must be a base64 Ed25519 key (64 bytes)")
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(raw), msg)), nil
}

// VerifySignature checks a base64 signature over msg against a base64
// public key.
func VerifySignature(public string, msg, sig []byte) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(public))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return errors.New("public key is not a base64 Ed25519 key")
	}
	s, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(s) != ed25519.SignatureSize {
		return errors.New("signature is not a base64 Ed25519 signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(raw), msg, s) {
		return errors.New("signature does not match the configured public key")
	}
	return nil
}

// checksumFor finds the SHA-256 (hex) of name in a SHA256SUMS file.
func checksumFor(sums []byte, name string) (string, error) {
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || strings.TrimPrefix(f[1], "*") != name {
			continue
		}
		h := strings.ToLower(f[0])
		if len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
			return "", fmt.Errorf("SHA256SUMS: bad digest for %s", name)
		}
		return h, nil
	}
	return "", fmt.Errorf("SHA256SUMS has no entry for %s", name)
}
