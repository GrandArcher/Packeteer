package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/herd"
)

// testdata/rpki-client.json is the output of rpki-client 9.5
// ("rpki-client -j -f") for a repository built by lab/mkrpki with
// a:64496:a b:64497:b seed:64498:d tampered:64498:c:tampered
// expired:64498:c:expired, the checklists of lab/e2e-herd.sh.
func TestChecklistsListOnlyWhatRPKIClientValidated(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "rpki-client.json"))
	if err != nil {
		t.Fatal(err)
	}
	gen := time.Date(2026, 11, 21, 3, 0, 0, 0, time.UTC)
	l, err := checklists(raw, gen)
	if err != nil {
		t.Fatal(err)
	}
	// Every valid checklist ends at its signature path's expiry, here the
	// CRL's next update, before its EE certificate's own end.
	end := time.Unix(1795403810, 0).UTC()
	want := []herd.Checklist{
		{ASNs: []uint32{64496}, Digests: []string{"7a15c50d5f4b0c8da9dd9c8b0ffb8cad87e650ab33a020c41484372efe31869b"}, NotAfter: end},
		{ASNs: []uint32{64497}, Digests: []string{"2e7b75a7f161e1efc28d42eb8d38c6b242c62097850c830d52baf994e90ed76d"}, NotAfter: end},
		{ASNs: []uint32{64498}, Digests: []string{"eecbccfa66c487d8ed9db18d17fce0deafa78d0b24a8bc7e64b3622f08117ee0"}, NotAfter: end},
	}
	if l.Schema != herd.IdentitySchema || !l.GeneratedAt.Equal(gen) || !reflect.DeepEqual(l.Checklists, want) {
		t.Fatalf("checklists = %+v, want %+v", l, want)
	}
	// c's key is named only by the expired and the tampered checklists,
	// which rpki-client refused.
	if !strings.Contains(string(raw), "Rt4Be5nIyD/oTf6td6AGO1W/pdUfQxnJCQZ9e9HE0hg=") || !strings.Contains(string(raw), `"validation": "Failed"`) {
		t.Fatal("fixture no longer holds the refused checklist of c's key")
	}
	for _, c := range l.Checklists {
		if c.Digests[0] == "46de017b99c8c83fe84dfead77a0063b55bfa5d51f4319c909067d7bd1c4d218" {
			t.Fatalf("a refused checklist is listed: %+v", c)
		}
	}
}

func TestChecklistsSkipWhatNamesNoASNAndRefuseABadDigest(t *testing.T) {
	const d = "ehXFDV9LDI2p3ZyLD/uMrYfmUKszoCDEFIQ3Lv4xhps="
	l, err := checklists([]byte(`
{"file": "r.sig", "type": "rsc", "validation": "OK", "valid_until": 1795835576,
 "signed_with_resources": [{"asrange": {"min": 64496, "max": 64511}}, {"ip_prefix": "192.0.2.0/24"}],
 "filenamesandhashes": [{"hash_digest": "`+d+`"}]}
{"file": "roa.roa", "type": "roa", "validation": "OK", "valid_until": 1795835576}
{"file": "s.sig", "type": "rsc", "validation": "OK", "valid_until": 1795835576,
 "signed_with_resources": [{"asid": 64499}], "filenamesandhashes": [{"hash_digest": "`+d+`"}]}`), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Checklists) != 1 || l.Checklists[0].ASNs[0] != 64499 || !l.Checklists[0].NotAfter.Equal(time.Unix(1795835576, 0)) {
		t.Fatalf("want only s.sig, ending at valid_until without an expires: %+v", l.Checklists)
	}
	for _, bad := range []string{`{"type": "rsc", "validation": "OK", "signed_with_resources": [{"asid": 64499}], "filenamesandhashes": [{"hash_digest": "AAAA"}]}`, `{"type": `} {
		if _, err := checklists([]byte(bad), time.Now()); err == nil {
			t.Fatalf("checklists(%s) did not fail", bad)
		}
	}
	if l, err := checklists(nil, time.Now()); err != nil || l.Checklists == nil || len(l.Checklists) != 0 {
		t.Fatalf("empty output: %+v, %v; want an empty list", l, err)
	}
}
