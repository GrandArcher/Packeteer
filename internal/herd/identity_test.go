package herd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

func checklistDoc(t *testing.T, lists ...Checklist) []byte {
	t.Helper()
	b, err := json.Marshal(IdentityList{Schema: IdentitySchema, GeneratedAt: t0, Checklists: lists})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseIdentityListBindsKeysToTheChecklistASNs(t *testing.T) {
	a, b := testNode(t), testNode(t)
	set, err := ParseIdentityList(checklistDoc(t,
		Checklist{ASNs: []uint32{64501, 64502}, Digests: []string{a.ID()}, NotAfter: t0.Add(time.Hour)},
		Checklist{ASNs: []uint32{64503}, Digests: []string{b.ID()}, NotAfter: t0.Add(time.Minute)},
		Checklist{ASNs: []uint32{64503}, Digests: []string{b.ID()}, NotAfter: t0.Add(2 * time.Hour)},
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 3 || !set[binding{64502, a.ID()}].Equal(t0.Add(time.Hour)) || !set[binding{64503, b.ID()}].Equal(t0.Add(2*time.Hour)) {
		t.Errorf("bindings = %v", set)
	}
	if _, ok := set[binding{64503, a.ID()}]; ok {
		t.Error("a key is bound to an ASN no checklist lists it under")
	}
	for name, raw := range map[string]string{
		"schema":        `{"schema":"other/1","checklists":[]}`,
		"unknown field": `{"schema":"` + IdentitySchema + `","checklists":[],"trust":true}`,
		"no digests":    `{"schema":"` + IdentitySchema + `","checklists":[{"asns":[64501],"digests":[],"not_after":"2027-01-01T00:00:00Z"}]}`,
		"bad digest":    `{"schema":"` + IdentitySchema + `","checklists":[{"asns":[64501],"digests":["AB"],"not_after":"2027-01-01T00:00:00Z"}]}`,
		"asn zero":      `{"schema":"` + IdentitySchema + `","checklists":[{"asns":[0],"digests":["` + a.ID() + `"],"not_after":"2027-01-01T00:00:00Z"}]}`,
		"no not_after":  `{"schema":"` + IdentitySchema + `","checklists":[{"asns":[64501],"digests":["` + a.ID() + `"]}]}`,
		"oversized":     `{"schema":"` + IdentitySchema + `","pad":"` + strings.Repeat("x", MaxIdentityBytes) + `"}`,
	} {
		if _, err := ParseIdentityList([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// One identity per ASN: a key verifies only for the ASN its checklist
// lists, only until not_after, and a failed refresh keeps the last list.
func TestIdentitiesVerifyByASNAndKeyUntilNotAfter(t *testing.T) {
	a, b := testNode(t), testNode(t)
	var mu sync.Mutex
	body, status := checklistDoc(t, Checklist{ASNs: []uint32{64501}, Digests: []string{a.ID()}, NotAfter: t0.Add(time.Hour)}), http.StatusOK
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	now := t0
	ids := NewIdentities(&config.HerdIdentity{URL: srv.URL + "/rsc.json?token=x", Refresh: time.Hour}, func() time.Time { return now }, quietLog(), nil)
	ids.client = srv.Client()

	if ids.Verified(64501, a.ID()) {
		t.Fatal("verified before the first fetch")
	}
	ids.Refresh(context.Background())
	if !ids.Verified(64501, a.ID()) || ids.Verified(64502, a.ID()) || ids.Verified(64501, b.ID()) {
		t.Error("verification must need both the ASN and the key of one checklist")
	}
	if st := ids.Status(); st.Bindings != 1 || st.LastError != "" || strings.Contains(st.URL, "token") {
		t.Errorf("status = %+v", st)
	}

	mu.Lock()
	status = http.StatusBadGateway
	mu.Unlock()
	ids.Refresh(context.Background())
	if !ids.Verified(64501, a.ID()) || ids.Status().LastError == "" {
		t.Errorf("a failed refresh dropped the last list or hid the error: %+v", ids.Status())
	}
	now = t0.Add(2 * time.Hour)
	if ids.Verified(64501, a.ID()) {
		t.Error("verified after not_after")
	}
	var none *Identities
	if none.Verified(64501, a.ID()) {
		t.Error("a nil source verified a member")
	}
}
