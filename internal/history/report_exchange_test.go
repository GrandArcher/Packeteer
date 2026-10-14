package history

import (
	"reflect"
	"testing"
)

var testPeers = map[string]string{"transit-b": "ix-lab", "transit-a": "ix-lab", "ix-quiet": "ix-other"}

func TestExchangesReport(t *testing.T) {
	rows := build(t, ReportExchanges, func(q *Query) { q.Exchanges = testPeers }).Rows.([]ExchangeRow)
	want := []ExchangeRow{
		{Exchange: "ix-lab", Peer: "transit-a", Improvements: 1, Active: 1, Prefixes: 1, VolumeMbps: 50, SteeredHours: 2},
		// transit-b: improvements 1, 2, and 3 started in the range (0 started
		// before it); 2 and 3 are active at now. pfxA has no recorded rate on
		// its records, so it takes the prefix's 5; pfxB's record says 100.
		// Hours: 2 + 5 + 4 + 1 (improvement 0 inside the range).
		{Exchange: "ix-lab", Peer: "transit-b", Improvements: 3, Active: 2, Prefixes: 2, VolumeMbps: 105, SteeredHours: 12},
		// A configured peer with no improvement still has a row.
		{Exchange: "ix-other", Peer: "ix-quiet"},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows\n got %+v\nwant %+v", rows, want)
	}
}

// A provider that is not an exchange peer never has a row, and a report
// built without peers is empty rather than null.
func TestExchangesReportOnlyPeers(t *testing.T) {
	rows := build(t, ReportExchanges, func(q *Query) { q.Exchanges = map[string]string{"transit-a": "ix-lab"} }).Rows.([]ExchangeRow)
	if len(rows) != 1 || rows[0].Peer != "transit-a" {
		t.Fatalf("rows = %+v", rows)
	}
	if rows := build(t, ReportExchanges).Rows.([]ExchangeRow); rows == nil || len(rows) != 0 {
		t.Fatalf("no exchanges: %#v", rows)
	}
}

func TestExchangesReportFilters(t *testing.T) {
	rows := build(t, ReportExchanges, func(q *Query) { q.Exchanges = testPeers; q.Provider = "transit-b" }).Rows.([]ExchangeRow)
	if len(rows) != 1 || rows[0].Peer != "transit-b" || rows[0].Improvements != 3 {
		t.Fatalf("provider filter: %+v", rows)
	}
	// Improvement 3 is the only cost one: the cause filter narrows the
	// improvements before they are counted, so pfxA drops out.
	rows = build(t, ReportExchanges, func(q *Query) { q.Exchanges = testPeers; q.Provider = "transit-b"; q.Cause = "cost" }).Rows.([]ExchangeRow)
	if len(rows) != 1 || rows[0].Improvements != 1 || rows[0].Prefixes != 1 || rows[0].VolumeMbps != 100 {
		t.Fatalf("cause filter: %+v", rows)
	}
}
