// Command mkcerts writes a throwaway CA and one certificate per instance
// name for the multi-POP lab (lab/e2e-multipop.sh, #30). Each certificate
// names the instance as CN and DNS SAN and is valid for a day. The files
// are generated on every run in a temporary directory and never committed.
//
// With -revoke NAME it also writes two CA-signed revocation lists for the
// probe agent lab (lab/e2e-agents.sh, #478): empty.crl lists nothing and
// revoked.crl lists NAME's certificate. The CA key is not kept, so both are
// made up front and the script swaps one for the other.
//
// Usage: mkcerts [-revoke NAME] DIR NAME...
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	revoke := flag.String("revoke", "", "also write empty.crl and revoked.crl, the latter listing this NAME's certificate")
	flag.Parse()
	if flag.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "usage: mkcerts [-revoke NAME] DIR NAME...")
		os.Exit(2)
	}
	if err := run(flag.Arg(0), flag.Args()[1:], *revoke); err != nil {
		fmt.Fprintln(os.Stderr, "mkcerts:", err)
		os.Exit(1)
	}
}

func run(dir string, names []string, revoke string) error {
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "packeteer-lab-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "ca.crt"), "CERTIFICATE", caDER); err != nil {
		return err
	}
	var revokedSerial *big.Int
	for i, name := range names {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			return err
		}
		if name == revoke {
			revokedSerial = tmpl.SerialNumber
		}
		kder, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
		if err := writePEM(filepath.Join(dir, name+".crt"), "CERTIFICATE", der); err != nil {
			return err
		}
		if err := writePEM(filepath.Join(dir, name+".key"), "EC PRIVATE KEY", kder); err != nil {
			return err
		}
	}
	if revoke == "" {
		return nil
	}
	if revokedSerial == nil {
		return fmt.Errorf("-revoke %q is not one of the names", revoke)
	}
	if err := writeCRL(filepath.Join(dir, "empty.crl"), now, caCert, caKey, nil); err != nil {
		return err
	}
	return writeCRL(filepath.Join(dir, "revoked.crl"), now, caCert, caKey, revokedSerial)
}

func writeCRL(path string, now time.Time, ca *x509.Certificate, key *ecdsa.PrivateKey, revoked *big.Int) error {
	var entries []x509.RevocationListEntry
	if revoked != nil {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: revoked, RevocationTime: now})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(24 * time.Hour),
		RevokedCertificateEntries: entries,
	}, ca, key)
	if err != nil {
		return err
	}
	return writePEM(path, "X509 CRL", der)
}

// writePEM uses 0644: the lab mounts the directory read-only into
// containers, and these keys protect nothing outside one lab run.
func writePEM(path, kind string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o644)
}
