package herd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Node is this instance's herd identity: one Ed25519 key that signs every
// response and backs a self-signed TLS certificate. Peers pin the public
// key, not an issuer.
type Node struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	cert tls.Certificate
}

// KeyID is the member id carried in responses: the hex SHA-256 of the
// public key.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// LoadNode reads the key at path, or creates it (mode 0600, directory
// 0700) when the file is absent. The key never leaves the node.
func LoadNode(path string) (*Node, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return createNode(path)
	}
	if err != nil {
		return nil, fmt.Errorf("herd key_file: %w", err)
	}
	blk, _ := pem.Decode(data)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("herd key_file %s: not a PKCS#8 PEM private key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("herd key_file %s: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("herd key_file %s: not an Ed25519 key", path)
	}
	return newNode(priv)
}

func createNode(path string) (*Node, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("herd key_file dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("herd key_file: %w", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return newNode(priv)
}

func newNode(priv ed25519.PrivateKey) (*Node, error) {
	pub := priv.Public().(ed25519.PublicKey)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "packeteer-herd"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	return &Node{priv: priv, pub: pub, cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}}, nil
}

// ID is this node's key id.
func (n *Node) ID() string { return KeyID(n.pub) }

// PublicKey is the form a peer puts in its config: "ed25519:" and the
// base64 of the public key.
func (n *Node) PublicKey() string { return "ed25519:" + base64.StdEncoding.EncodeToString(n.pub) }

// sign signs the canonical form of v, which must have an empty signature.
func (n *Node) sign(v any) (string, error) {
	c, err := Canonical(v)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(n.priv, c)), nil
}

// verifyDocument checks the signature of a signed JSON document: the
// canonical form of everything except "signature". It returns an error for
// a missing, malformed, or wrong signature.
func verifyDocument(pub ed25519.PublicKey, raw []byte) error {
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return err
	}
	sigText, _ := generic["signature"].(string)
	delete(generic, "signature")
	sig, err := base64.StdEncoding.DecodeString(sigText)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("missing or malformed signature")
	}
	c, err := Canonical(generic)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, c, sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

// pinned returns a VerifyPeerCertificate that accepts only a certificate
// whose public key is one of keys. The handshake fails otherwise, before
// any request is parsed.
func pinned(keys map[string]ed25519.PublicKey) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("no certificate")
		}
		c, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		pub, ok := c.PublicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("certificate key is not Ed25519")
		}
		if _, ok := keys[KeyID(pub)]; !ok {
			return errors.New("key is not pinned")
		}
		return nil
	}
}
