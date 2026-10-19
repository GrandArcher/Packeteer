package herd

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// testEntry is a valid entry for n at t0.
func testEntry(n *Node) Entry {
	return Entry{
		ASN:           64501,
		Nodes:         []EntryNode{{Key: n.PublicKey(), URL: "https://192.0.2.30:9444"}},
		RetentionDays: 90,
		Classes:       []string{"measurements", "paths"},
		Issued:        t0,
		Expires:       t0.Add(90 * 24 * time.Hour),
	}
}

func signed(t *testing.T, n *Node, e Entry) []byte {
	t.Helper()
	raw, err := n.SignEntry(e)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCheckEntryAcceptsASignedEntry(t *testing.T) {
	n := testNode(t)
	e := testEntry(n)
	e.Identity = &EntryIdentity{StatementURL: "https://example.net/id.json", StatementSHA256: strings.Repeat("ab", 32), RSCURL: "https://example.net/id.rsc"}
	raw := signed(t, n, e)

	got, err := CheckEntry(raw, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got.ASN != 64501 || got.Signer != n.PublicKey() || got.Schema != EntrySchema || len(got.Nodes) != 1 || got.Identity == nil || got.Signature == "" {
		t.Errorf("entry = %+v", got)
	}
	// The signature is over the canonical form, not the bytes: a hub that
	// re-indents the document does not break it.
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	compact, _ := json.Marshal(generic)
	if _, err := CheckEntry(compact, t0.Add(time.Hour)); err != nil {
		t.Errorf("re-encoded entry: %v", err)
	}
}

func TestCheckEntryRefusals(t *testing.T) {
	n, other := testNode(t), testNode(t)
	now := t0.Add(time.Hour)
	edit := func(f func(*Entry)) []byte {
		e := testEntry(n)
		f(&e)
		return signed(t, n, e)
	}
	tamper := func(f func(map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(signed(t, n, testEntry(n)), &m); err != nil {
			t.Fatal(err)
		}
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"asn changed after signing", tamper(func(m map[string]any) { m["asn"] = 64502 }), "signature does not verify"},
		{"url changed after signing", tamper(func(m map[string]any) {
			m["nodes"].([]any)[0].(map[string]any)["url"] = "https://192.0.2.99:9444"
		}), "signature does not verify"},
		{"unsigned", tamper(func(m map[string]any) { delete(m, "signature") }), "signature"},
		{"unknown field", tamper(func(m map[string]any) { m["extra"] = 1 }), "unknown field"},
		{"signed by a key that is not a node", func() []byte {
			e := testEntry(n)
			e.Nodes[0].Key = other.PublicKey()
			return signed(t, n, e)
		}(), "signer is not one of the nodes"},
		{"asn 0", edit(func(e *Entry) { e.ASN = 0 }), "asn must not be 0"},
		{"no nodes", edit(func(e *Entry) { e.Nodes = nil }), "needs 1 to 4 nodes"},
		{"too many nodes", edit(func(e *Entry) {
			for range MaxEntryNodes {
				e.Nodes = append(e.Nodes, EntryNode{Key: testNode(t).PublicKey(), URL: "https://192.0.2.31:9444"})
			}
		}), "needs 1 to 4 nodes"},
		{"duplicate url", edit(func(e *Entry) {
			e.Nodes = append(e.Nodes, EntryNode{Key: other.PublicKey(), URL: e.Nodes[0].URL})
		}), "duplicate"},
		{"http endpoint", edit(func(e *Entry) { e.Nodes[0].URL = "http://192.0.2.30:9444" }), "https"},
		{"endpoint without port", edit(func(e *Entry) { e.Nodes[0].URL = "https://node.example.net" }), "port"},
		{"loopback endpoint", edit(func(e *Entry) { e.Nodes[0].URL = "https://127.0.0.1:9444" }), "not a routable address"},
		{"link-local endpoint", edit(func(e *Entry) { e.Nodes[0].URL = "https://[fe80::1]:9444" }), "not a routable address"},
		{"retention too short", edit(func(e *Entry) { e.RetentionDays = 7 }), "retention_days"},
		{"no class", edit(func(e *Entry) { e.Classes = nil }), "data class"},
		{"unknown class", edit(func(e *Entry) { e.Classes = []string{"flows"} }), "classes[0]"},
		{"repeated class", edit(func(e *Entry) { e.Classes = []string{"paths", "paths"} }), "repeated"},
		{"identity over http", edit(func(e *Entry) {
			e.Identity = &EntryIdentity{StatementURL: "http://example.net/id.json", StatementSHA256: strings.Repeat("ab", 32), RSCURL: "https://example.net/id.rsc"}
		}), "must be https"},
		{"identity digest", edit(func(e *Entry) {
			e.Identity = &EntryIdentity{StatementURL: "https://example.net/id.json", StatementSHA256: "ABC", RSCURL: "https://example.net/id.rsc"}
		}), "statement_sha256"},
		{"issued in the future", edit(func(e *Entry) { e.Issued = now.Add(time.Hour); e.Expires = e.Issued.Add(time.Hour) }), "future"},
		{"expires before issued", edit(func(e *Entry) { e.Expires = e.Issued.Add(-time.Hour) }), "after issued"},
		{"lives too long", edit(func(e *Entry) { e.Expires = e.Issued.Add(MaxEntryLife + time.Hour) }), "within"},
		{"expiry pushed out by a late clock", edit(func(e *Entry) { e.Issued = now; e.Expires = now.Add(MaxEntryLife + time.Hour) }), "within"},
		{"expired", edit(func(e *Entry) { e.Expires = t0.Add(time.Minute) }), "expired"},
		{"oversized", append(signed(t, n, testEntry(n)), make([]byte, MaxEntryBytes)...), "larger than"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := CheckEntry(c.raw, now)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one containing %q", err, c.want)
			}
		})
	}
}

func TestCheckEntryExpiryIsAnErrExpired(t *testing.T) {
	n := testNode(t)
	raw := signed(t, n, testEntry(n))
	if _, err := CheckEntry(raw, t0.Add(91*24*time.Hour)); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
	if _, err := CheckEntry(raw, t0.Add(89*24*time.Hour)); err != nil {
		t.Errorf("a day before expiry: %v", err)
	}
}
