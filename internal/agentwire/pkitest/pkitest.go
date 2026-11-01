// Package pkitest makes a throwaway CA, leaf certificates, and CRLs for the
// agent tests (#230). Test code only; nothing here is used at runtime.
package pkitest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CA signs the test certificates.
type CA struct {
	Dir    string
	CAFile string
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	serial int64
}

// Leaf is an issued certificate and its files.
type Leaf struct {
	CertFile, KeyFile string
	Serial            *big.Int
}

func write(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// New creates a CA in a temporary directory.
func New(t *testing.T) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca := &CA{Dir: t.TempDir(), cert: cert, key: key, serial: 1}
	ca.CAFile = filepath.Join(ca.Dir, "ca.crt")
	write(t, ca.CAFile, "CERTIFICATE", der)
	return ca
}

// Issue makes a certificate with common name cn, valid for both server and
// client use, and for the loopback address.
func (ca *CA) Issue(t *testing.T, cn string) Leaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca.serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(ca.serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{cn}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	l := Leaf{CertFile: filepath.Join(ca.Dir, cn+".crt"), KeyFile: filepath.Join(ca.Dir, cn+".key"), Serial: tmpl.SerialNumber}
	write(t, l.CertFile, "CERTIFICATE", der)
	write(t, l.KeyFile, "EC PRIVATE KEY", kder)
	return l
}

// WriteCRL writes a CA-signed CRL listing the given leaves to path.
// number must grow with each list written to the same path.
func (ca *CA) WriteCRL(t *testing.T, path string, number int64, revoked ...Leaf) {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, l := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: l.Serial, RevocationTime: time.Now()})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(number), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: entries,
	}, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	write(t, path, "X509 CRL", der)
}
