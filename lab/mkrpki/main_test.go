package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/herd"
)

// That rpki-client accepts the valid objects and refuses the tampered and
// expired ones is shown by lab/e2e-herd.sh and lab/herdhub's fixture; this
// test checks the objects' structure and signatures.
func TestBuildSignsOneChecklistPerSpec(t *testing.T) {
	dir, keys := t.TempDir(), t.TempDir()
	ids := map[string]string{}
	for _, k := range []string{"a", "c"} {
		n, err := herd.LoadNode(filepath.Join(keys, k+".key"))
		if err != nil {
			t.Fatal(err)
		}
		ids[k] = n.ID()
	}
	now := time.Now()
	if err := run([]string{dir, keys, "a:64496:a", "tampered:64498:c:tampered", "expired:64498:c:expired"}); err != nil {
		t.Fatal(err)
	}

	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	ta, err := x509.ParseCertificate(read("cache/ta/lab/ta.cer"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ta.CheckSignatureFrom(ta); err != nil || !ta.IsCA || len(ta.AuthorityKeyId) != 0 {
		t.Fatalf("trust anchor is not a self-signed CA: %v", err)
	}
	if ext := extension(ta, oidASIdentifiers); !ext.Critical || !bytes.Equal(ext.Value, mustMarshal(taASIdentifiers{[]asRange{{64496, 64511}}})) {
		t.Fatalf("trust anchor AS resources: %+v", ext)
	}
	tal := strings.Split(string(read("lab.tal")), "\n")
	spki, _ := x509.MarshalPKIXPublicKey(ta.PublicKey)
	if tal[0] != "rsync://rpki.example.net/ta/ta.cer" || tal[1] != "" || tal[2] != base64.StdEncoding.EncodeToString(spki) {
		t.Fatalf("TAL does not name the trust anchor: %q", tal)
	}
	crl, err := x509.ParseRevocationList(read("cache/rpki.example.net/repo/ta.crl"))
	if err != nil || crl.CheckSignatureFrom(ta) != nil || !bytes.Equal(crl.AuthorityKeyId, ta.SubjectKeyId) || !crl.NextUpdate.After(now) {
		t.Fatalf("CRL is not the trust anchor's current one: %v", err)
	}

	for _, tc := range []struct {
		name, key                string
		asn                      int64
		signatureCovers, expired bool
	}{
		{"a", "a", 64496, true, false},
		{"tampered", "c", 64498, false, false},
		{"expired", "c", 64498, true, true},
	} {
		ee, content, digestOK := parseObject(t, read("rsc/"+tc.name+".sig"))
		if err := ee.CheckSignatureFrom(ta); err != nil {
			t.Fatalf("%s: EE certificate not issued by the trust anchor: %v", tc.name, err)
		}
		if ee.IssuingCertificateURL[0] != taURI || ee.CRLDistributionPoints[0] != crlURI || extension(ee, oidSubjectInfoAcc).Id != nil {
			t.Fatalf("%s: EE certificate must point at the trust anchor and CRL and carry no SIA", tc.name)
		}
		if ext := extension(ee, oidASIdentifiers); !bytes.Equal(ext.Value, mustMarshal(eeASIdentifiers{[]int64{tc.asn}})) {
			t.Fatalf("%s: EE AS resources: %x", tc.name, ext.Value)
		}
		if got := ee.NotAfter.Before(now); got != tc.expired {
			t.Fatalf("%s: EE certificate expired = %v, want %v", tc.name, got, tc.expired)
		}
		if digestOK != tc.signatureCovers {
			t.Fatalf("%s: signature covers the published checklist = %v, want %v", tc.name, digestOK, tc.signatureCovers)
		}
		var rsc signedChecklist
		if rest, err := asn1.Unmarshal(content, &rsc); err != nil || len(rest) != 0 {
			t.Fatalf("%s: checklist: %v", tc.name, err)
		}
		if rsc.Resources.ASID.ASNum[0] != tc.asn || len(rsc.CheckList) != 1 || rsc.CheckList[0].FileName != tc.key+".pub" ||
			hex.EncodeToString(rsc.CheckList[0].Hash) != ids[tc.key] {
			t.Fatalf("%s: checklist %+v does not bind AS%d to key id %s", tc.name, rsc, tc.asn, ids[tc.key])
		}
	}
}

// parseObject returns the EE certificate and the checklist of a signed
// object, and whether its signed attributes are signed by the EE key and
// hold the digest of that checklist.
func parseObject(t *testing.T, der []byte) (*x509.Certificate, []byte, bool) {
	t.Helper()
	var ci contentInfo
	var sd signedData
	if _, err := asn1.Unmarshal(der, &ci); err != nil || !ci.ContentType.Equal(oidSignedData) {
		t.Fatalf("content info: %v", err)
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("signed data: %v", err)
	}
	if sd.Version != 3 || !sd.EncapContentInfo.EContentType.Equal(oidSignedChecklist) || len(sd.SignerInfos) != 1 {
		t.Fatalf("signed data: %+v", sd)
	}
	ee, err := x509.ParseCertificate(sd.Certificates.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	si := sd.SignerInfos[0]
	if !bytes.Equal(si.SID, ee.SubjectKeyId) {
		t.Fatal("signer is not named by the EE certificate's key identifier")
	}
	set := mustMarshal(asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: si.SignedAttrs.Bytes})
	h := sha256.Sum256(set)
	if err := rsa.VerifyPKCS1v15(ee.PublicKey.(*rsa.PublicKey), crypto.SHA256, h[:], si.Signature); err != nil {
		t.Fatalf("signed attributes: %v", err)
	}
	var attrs []attribute
	if _, err := asn1.UnmarshalWithParams(set, &attrs, "set"); err != nil {
		t.Fatal(err)
	}
	content := sd.EncapContentInfo.EContent
	md := sha256.Sum256(content)
	for _, a := range attrs {
		if a.Type.Equal(oidMessageDigest) {
			var got []byte
			if _, err := asn1.Unmarshal(a.Values[0].FullBytes, &got); err != nil {
				t.Fatal(err)
			}
			return ee, content, bytes.Equal(got, md[:])
		}
	}
	t.Fatal("no message digest attribute")
	return nil, nil, false
}

func extension(c *x509.Certificate, id asn1.ObjectIdentifier) pkix.Extension {
	for _, x := range c.Extensions {
		if x.Id.Equal(id) {
			return x
		}
	}
	return pkix.Extension{}
}

func TestParseSpecRefusesWhatTheTrustAnchorCannotSign(t *testing.T) {
	if sp, err := parseSpec("seed:64499:d:expired"); err != nil || sp != (spec{"seed", 64499, "d", "expired"}) {
		t.Fatalf("parseSpec = %+v, %v", sp, err)
	}
	for _, s := range []string{"a:64496", "a:64512:a", "a:64495:a", "a:x:a", "a:64496:a:revoked", "../a:64496:a", "a:64496:a/b", "a:64496:a:expired:x"} {
		if _, err := parseSpec(s); err == nil {
			t.Errorf("parseSpec(%q) did not fail", s)
		}
	}
	keys := t.TempDir()
	if _, err := herd.LoadNode(filepath.Join(keys, "a.key")); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{t.TempDir(), keys, "a:64496:missing"}); err == nil {
		t.Error("a missing node key must fail, not create one")
	}
	if err := run([]string{t.TempDir(), keys, "a:64496:a", "a:64497:a"}); err == nil || !strings.Contains(err.Error(), "named twice") {
		t.Errorf("a checklist named twice: %v", err)
	}
	if err := run([]string{t.TempDir(), keys}); err != errUsage {
		t.Errorf("no SPEC: %v, want the usage", err)
	}
}
