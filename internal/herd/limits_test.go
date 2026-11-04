package herd

import (
	"fmt"
	"testing"
	"time"
)

// fill puts maxLimiterKeys documentation addresses in l, seen at at.
func fill(l *limiterSet, at time.Time) {
	for i := range maxLimiterKeys {
		l.reserve(fmt.Sprintf("2001:db8::%x", i+1), 1, at)
	}
}

// TestFullAddressTableAdmitsPinnedPeer: a per-address table full of other
// addresses seen inside the last minute still admits a pinned peer from a
// new address (#506).
func TestFullAddressTableAdmitsPinnedPeer(t *testing.T) {
	srv := newMember(t, 64501, nil)
	a := testNode(t)
	srv.serve(a)
	fill(srv.srv.byIP, t0.Add(-30*time.Second))
	if code, _, body := get(t, client(a, srv), srv.url()+PathStatus); code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	if n := tripCount(srv.trips, "rate_per_address"); n != 0 {
		t.Fatalf("rate_per_address trips = %d", n)
	}
	l := srv.srv.byIP
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.m) != maxLimiterKeys {
		t.Fatalf("table holds %d keys", len(l.m))
	}
	if e := l.m["127.0.0.1"]; e == nil || !e.pinned {
		t.Fatalf("peer entry = %+v", e)
	}
}

// TestEvictKeepsPinnedAddress: a full table drops the least recently seen
// address without a pinned handshake, even when a pinned one is older.
func TestEvictKeepsPinnedAddress(t *testing.T) {
	l := newLimiterSet(60)
	l.reserve("192.0.2.1", 30, t0)
	l.markPinned("192.0.2.1")
	for i := range maxLimiterKeys - 1 {
		l.reserve(fmt.Sprintf("2001:db8::%x", i+1), 1, t0.Add(time.Duration(i+1)*time.Millisecond))
	}
	if ok, _ := l.reserve("198.51.100.1", 1, t0.Add(10*time.Second)); !ok {
		t.Fatal("new address refused")
	}
	if len(l.m) != maxLimiterKeys {
		t.Fatalf("table holds %d keys", len(l.m))
	}
	if _, ok := l.m["2001:db8::1"]; ok {
		t.Fatal("least recently seen unpinned address kept")
	}
	// The pinned address kept its bucket: 30 spent, 10 refilled, 40 left.
	if ok, _ := l.reserve("192.0.2.1", 45, t0.Add(10*time.Second)); ok {
		t.Fatal("pinned address bucket was reset")
	}

	// Entries idle past a minute go first, and all of them.
	if ok, _ := l.reserve("198.51.100.2", 1, t0.Add(2*time.Minute)); !ok {
		t.Fatal("new address refused after idle")
	}
	if len(l.m) != 1 {
		t.Fatalf("idle entries kept: %d", len(l.m))
	}
}
