// Command mkrpki builds the in-lab RPKI repository of the herd lab
// (lab/e2e-herd.sh, #708): a trust anchor that holds the documentation ASNs
// 64496-64511, its TAL and CRL, and one RPKI Signed Checklist (RFC 9323) per
// SPEC, each signed by its own EE certificate under the trust anchor. A
// checklist binds an ASN to a herd node key: its one entry is the node's
// public key, so the entry's digest is the node's key id. The lab
// rpki-client validates the checklists against this repository offline;
// nothing is fetched from or published to a live repository. Keys are
// generated on every run and never committed.
//
// Usage: mkrpki DIR KEYDIR SPEC...
//
// SPEC is NAME:ASN:KEY or NAME:ASN:KEY:STATE. KEY names the herd node key
// KEYDIR/KEY.key. STATE is "tampered" (the published checklist names KEY,
// but the CA signed a different digest) or "expired" (its EE certificate
// ended an hour ago). DIR receives lab.tal, the rpki-client cache in cache/
// (the trust anchor in ta/lab/ and the CRL under the repository URI), and
// rsc/NAME.sig.
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/herd"
)

// The repository's rsync URIs. rpki-client in file mode never fetches them:
// it maps each to a path under its cache directory. example.net is reserved
// for documentation (RFC 2606).
const (
	host    = "rpki.example.net"
	taURI   = "rsync://" + host + "/ta/ta.cer"
	repoURI = "rsync://" + host + "/repo/"
	crlURI  = repoURI + "ta.crl"
	mftURI  = repoURI + "ta.mft"
	talName = "lab"
)

// The trust anchor's AS resources: the 16-bit documentation ASNs (RFC 5398).
const taASMin, taASMax = 64496, 64511

var (
	oidSHA256           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSignedData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSignedChecklist  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 48}
	oidCertPolicies     = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidRPKIPolicy       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 14, 2}
	oidASIdentifiers    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 8}
	oidSubjectInfoAcc   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11}
	oidCARepository     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 5}
	oidRPKIManifest     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 10}
	sha256Algorithm     = pkix.AlgorithmIdentifier{Algorithm: oidSHA256}
	rsaEncryptionAlgo   = pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue}
	portableFilename    = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*$`)
	errUsage            = errors.New("usage: mkrpki DIR KEYDIR NAME:ASN:KEY[:tampered|:expired] [SPEC]")
	certificatePolicies = pkix.Extension{Id: oidCertPolicies, Critical: true, Value: mustMarshal([]policyInformation{{oidRPKIPolicy}})}
)

type policyInformation struct{ ID asn1.ObjectIdentifier }

type accessDescription struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

type asRange struct{ Min, Max int64 }

// RFC 3779 ASIdentifiers with an asIdsOrRanges choice of ranges (the trust
// anchor) or of single ASNs (an EE certificate).
type taASIdentifiers struct {
	ASNum []asRange `asn1:"explicit,tag:0"`
}

type eeASIdentifiers struct {
	ASNum []int64 `asn1:"explicit,tag:0"`
}

// RFC 9323 RpkiSignedChecklist with the default version and only AS
// resources.
type signedChecklist struct {
	Resources       resourceBlock
	DigestAlgorithm pkix.AlgorithmIdentifier
	CheckList       []fileNameAndHash
}

type resourceBlock struct {
	ASID eeASIdentifiers `asn1:"explicit,tag:0"`
}

type fileNameAndHash struct {
	FileName string `asn1:"ia5"`
	Hash     []byte
}

// RFC 6488 signed object (CMS SignedData, RFC 5652).
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue
	SignerInfos      []signerInfo `asn1:"set"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,tag:0"`
}

type signerInfo struct {
	Version            int
	SID                []byte `asn1:"tag:0"`
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// spec is one checklist to sign.
type spec struct {
	name  string
	asn   int64
	key   string
	state string
}

func parseSpec(s string) (spec, error) {
	f := strings.Split(s, ":")
	if len(f) < 3 || len(f) > 4 {
		return spec{}, fmt.Errorf("%q: want NAME:ASN:KEY[:STATE]", s)
	}
	sp := spec{name: f[0], key: f[2]}
	if len(f) == 4 {
		sp.state = f[3]
	}
	asn, err := strconv.ParseInt(f[1], 10, 64)
	switch {
	case !portableFilename.MatchString(sp.name) || !portableFilename.MatchString(sp.key):
		return spec{}, fmt.Errorf("%q: NAME and KEY must be portable file names", s)
	case err != nil || asn < taASMin || asn > taASMax:
		return spec{}, fmt.Errorf("%q: ASN must be in the trust anchor's AS%d-AS%d", s, taASMin, taASMax)
	case sp.state != "" && sp.state != "tampered" && sp.state != "expired":
		return spec{}, fmt.Errorf("%q: STATE must be tampered or expired", s)
	}
	sp.asn = asn
	return sp, nil
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// keyID is the RFC 6487 subject key identifier: the SHA-1 of the subject
// public key bit string.
func keyID(pub *rsa.PublicKey) []byte {
	h := sha1.Sum(x509.MarshalPKCS1PublicKey(pub))
	return h[:]
}

func uri(s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(s)}
}

// authority is the trust anchor: it issues every EE certificate and the CRL.
type authority struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
	der  []byte
}

func newAuthority(now time.Time) (*authority, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	sia := mustMarshal([]accessDescription{{oidCARepository, uri(repoURI)}, {oidRPKIManifest, uri(mftURI)}})
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "packeteer-lab-ta"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          keyID(&key.PublicKey),
		ExtraExtensions: []pkix.Extension{
			certificatePolicies,
			{Id: oidSubjectInfoAcc, Value: sia},
			{Id: oidASIdentifiers, Critical: true, Value: mustMarshal(taASIdentifiers{[]asRange{{taASMin, taASMax}}})},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &authority{key: key, cert: cert, der: der}, nil
}

// tal is the RFC 8630 trust anchor locator of a.
func (a *authority) tal() ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(&a.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return []byte(taURI + "\n\n" + base64.StdEncoding.EncodeToString(spki) + "\n"), nil
}

func (a *authority) crl(now time.Time) ([]byte, error) {
	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(2 * 24 * time.Hour),
	}, a.cert, a.key)
}

// checklist returns the RSC of sp, with digest the SHA-256 of the node
// key named by sp. serial must be unique under a.
func (a *authority) checklist(sp spec, digest []byte, serial int64, now time.Time) ([]byte, error) {
	notBefore, notAfter := now.Add(-time.Hour), now.Add(7*24*time.Hour)
	if sp.state == "expired" {
		notBefore, notAfter = now.Add(-48*time.Hour), now.Add(-time.Hour)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	ski := keyID(&key.PublicKey)
	ee, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: sp.name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SubjectKeyId:          ski,
		IssuingCertificateURL: []string{taURI},
		CRLDistributionPoints: []string{crlURI},
		ExtraExtensions: []pkix.Extension{
			certificatePolicies,
			{Id: oidASIdentifiers, Critical: true, Value: mustMarshal(eeASIdentifiers{[]int64{sp.asn}})},
		},
	}, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	content := func(d []byte) []byte {
		return mustMarshal(signedChecklist{
			Resources:       resourceBlock{eeASIdentifiers{[]int64{sp.asn}}},
			DigestAlgorithm: sha256Algorithm,
			CheckList:       []fileNameAndHash{{sp.key + ".pub", d}},
		})
	}
	shown := content(digest)
	signed := shown
	if sp.state == "tampered" {
		other := bytes.Clone(digest)
		other[len(other)-1] ^= 1
		signed = content(other)
	}
	obj, err := signObject(signed, ee, ski, key, notBefore)
	if err != nil {
		return nil, err
	}
	// The tampered object names the key, but its signature covers the
	// other digest, so a relying party must refuse it.
	return bytes.Replace(obj, signed, shown, 1), nil
}

// signObject wraps eContent in an RFC 6488 signed object signed by key, the
// key of the EE certificate ee with subject key identifier ski.
func signObject(eContent, ee, ski []byte, key *rsa.PrivateKey, signingTime time.Time) ([]byte, error) {
	md := sha256.Sum256(eContent)
	attrs := [][]byte{
		mustMarshal(attribute{oidContentType, []asn1.RawValue{{FullBytes: mustMarshal(oidSignedChecklist)}}}),
		mustMarshal(attribute{oidMessageDigest, []asn1.RawValue{{FullBytes: mustMarshal(md[:])}}}),
		mustMarshal(attribute{oidSigningTime, []asn1.RawValue{{FullBytes: mustMarshal(signingTime.UTC())}}}),
	}
	// DER orders a SET OF by its encoded elements.
	slices.SortFunc(attrs, bytes.Compare)
	set := bytes.Join(attrs, nil)
	signedAttrs := mustMarshal(asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: set})
	h := sha256.Sum256(signedAttrs)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		return nil, err
	}
	sd, err := asn1.Marshal(signedData{
		Version:          3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{sha256Algorithm},
		EncapContentInfo: encapContentInfo{oidSignedChecklist, eContent},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: ee},
		SignerInfos: []signerInfo{{
			Version:            3,
			SID:                ski,
			DigestAlgorithm:    sha256Algorithm,
			SignedAttrs:        asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: set},
			SignatureAlgorithm: rsaEncryptionAlgo,
			Signature:          sig,
		}},
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(contentInfo{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sd}})
}

// build writes the repository of specs to dir, reading node keys from
// keyDir.
func build(dir, keyDir string, specs []spec, now time.Time) error {
	ta, err := newAuthority(now)
	if err != nil {
		return err
	}
	tal, err := ta.tal()
	if err != nil {
		return err
	}
	crl, err := ta.crl(now)
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"lab.tal": tal,
		filepath.Join("cache", "ta", talName, "ta.cer"):                ta.der,
		filepath.Join("cache", strings.TrimPrefix(crlURI, "rsync://")): crl,
	}
	for i, sp := range specs {
		node, err := herd.OpenNode(filepath.Join(keyDir, sp.key+".key"))
		if err != nil {
			return err
		}
		digest, err := hex.DecodeString(node.ID())
		if err != nil {
			return err
		}
		obj, err := ta.checklist(sp, digest, int64(i)+2, now)
		if err != nil {
			return fmt.Errorf("%s: %w", sp.name, err)
		}
		name := filepath.Join("rsc", sp.name+".sig")
		if _, dup := files[name]; dup {
			return fmt.Errorf("checklist %s named twice", sp.name)
		}
		files[name] = obj
	}
	for name, b := range files {
		path := filepath.Join(dir, name)
		// rpki-client drops to its own user, which must read the cache.
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func run(args []string) error {
	if len(args) < 3 {
		return errUsage
	}
	var specs []spec
	for _, a := range args[2:] {
		sp, err := parseSpec(a)
		if err != nil {
			return err
		}
		specs = append(specs, sp)
	}
	return build(args[0], args[1], specs, time.Now())
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mkrpki:", err)
		os.Exit(1)
	}
}
