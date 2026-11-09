package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func readPEM(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		t.Fatalf("%s: no PEM block", path)
	}
	return blk.Bytes
}

func TestRevokeWritesSignedListsNamingOnlyTheChosenCertificate(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, []string{"controller", "agent-a", "agent-b"}, "agent-b"); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(readPEM(t, filepath.Join(dir, "ca.crt")))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(readPEM(t, filepath.Join(dir, "agent-b.crt")))
	if err != nil {
		t.Fatal(err)
	}
	empty, err := x509.ParseRevocationList(readPEM(t, filepath.Join(dir, "empty.crl")))
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := x509.ParseRevocationList(readPEM(t, filepath.Join(dir, "revoked.crl")))
	if err != nil {
		t.Fatal(err)
	}
	for name, l := range map[string]*x509.RevocationList{"empty": empty, "revoked": revoked} {
		if err := l.CheckSignatureFrom(ca); err != nil {
			t.Errorf("%s.crl is not signed by the lab CA: %v", name, err)
		}
	}
	if len(empty.RevokedCertificateEntries) != 0 {
		t.Errorf("empty.crl lists %d certificates", len(empty.RevokedCertificateEntries))
	}
	if len(revoked.RevokedCertificateEntries) != 1 || revoked.RevokedCertificateEntries[0].SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Errorf("revoked.crl = %+v, want only agent-b serial %v", revoked.RevokedCertificateEntries, leaf.SerialNumber)
	}
}

func TestNoRevokeWritesNoLists(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, []string{"pop-a"}, ""); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"empty.crl", "revoked.crl"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Errorf("%s written without -revoke", f)
		}
	}
}

func TestRevokeOfUnknownNameFails(t *testing.T) {
	if err := run(t.TempDir(), []string{"agent-a"}, "agent-z"); err == nil {
		t.Fatal("revoking a name that has no certificate must fail")
	}
}
