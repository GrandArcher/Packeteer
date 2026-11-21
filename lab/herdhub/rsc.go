package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/GrandArcher/Packeteer/internal/herd"
)

// rpkiObject is what a checklist needs from one object of rpki-client's
// file-mode output (rpki-client -j -f, version 9).
type rpkiObject struct {
	File       string `json:"file"`
	Type       string `json:"type"`
	Validation string `json:"validation"`
	ValidUntil int64  `json:"valid_until"`
	Expires    int64  `json:"expires"`
	Resources  []struct {
		ASID *uint32 `json:"asid"`
	} `json:"signed_with_resources"`
	Files []struct {
		HashDigest string `json:"hash_digest"`
	} `json:"filenamesandhashes"`
}

// checklists returns the identity document of the RPKI Signed Checklists
// in raw, rpki-client's concatenated JSON. Only a checklist rpki-client
// reports as "OK" is listed: one it refused (tampered, expired, not under
// the trust anchor) binds nothing. AS ranges and IP resources name no
// single ASN and are not listed. A checklist ends at the expiry of its
// whole signature path (CRL and certificates), not only its EE
// certificate. A malformed digest fails the whole document, so the hub
// serves an error and every node keeps its last good one.
func checklists(raw []byte, generated time.Time) (herd.IdentityList, error) {
	l := herd.IdentityList{Schema: herd.IdentitySchema, GeneratedAt: generated.UTC(), Checklists: []herd.Checklist{}}
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		var o rpkiObject
		if err := dec.Decode(&o); errors.Is(err, io.EOF) {
			return l, nil
		} else if err != nil {
			return herd.IdentityList{}, fmt.Errorf("rpki-client output: %w", err)
		}
		if o.Type != "rsc" || o.Validation != "OK" {
			continue
		}
		c := herd.Checklist{NotAfter: time.Unix(o.ValidUntil, 0).UTC()}
		if o.Expires > 0 {
			c.NotAfter = time.Unix(o.Expires, 0).UTC()
		}
		for _, r := range o.Resources {
			if r.ASID != nil {
				c.ASNs = append(c.ASNs, *r.ASID)
			}
		}
		for _, f := range o.Files {
			d, err := base64.StdEncoding.DecodeString(f.HashDigest)
			if err != nil || len(d) != 32 {
				return herd.IdentityList{}, fmt.Errorf("%s: digest %q is not a base64 SHA-256", o.File, f.HashDigest)
			}
			c.Digests = append(c.Digests, hex.EncodeToString(d))
		}
		if len(c.ASNs) > 0 && len(c.Digests) > 0 {
			l.Checklists = append(l.Checklists, c)
		}
	}
}

// checklistDoc serves the identity document of the rpki-client output in
// path, dated when rpki-client last wrote it.
func checklistDoc(path string) func() ([]byte, error) {
	return func() ([]byte, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		st, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		l, err := checklists(raw, st.ModTime())
		if err != nil {
			return nil, err
		}
		return json.Marshal(l)
	}
}
