package history

import (
	"cmp"
	"net/netip"
	"slices"
	"strconv"
)

// ExchangeRow is one exchange peer over the range (#148).
type ExchangeRow struct {
	Exchange     string `json:"exchange"`
	Peer         string `json:"peer"`
	Improvements int    `json:"improvements"`
	Active       int    `json:"active"`
	Prefixes     int    `json:"prefixes"`
	// VolumeMbps is the observed rate of the prefixes steered onto the peer
	// in the range, each counted once at its latest improvement. Prefixes
	// with no known rate add nothing.
	VolumeMbps   float64 `json:"volume_mbps"`
	SteeredHours float64 `json:"steered_hours"`
}

// exchanges has one row per configured exchange peer, including peers with
// no improvement. Query.Exchanges names them; a provider that is not a peer
// is never a row.
func (a *agg) exchanges(rep *Report) {
	type acc struct {
		imps, active int
		hours        float64
		vol          map[netip.Prefix]float64
		latest       map[netip.Prefix]int
	}
	by := map[string]*acc{}
	for peer := range a.q.Exchanges {
		by[peer] = &acc{vol: map[netip.Prefix]float64{}, latest: map[netip.Prefix]int{}}
	}
	for i, r := range a.imps {
		x := by[r.Provider]
		if x == nil {
			continue
		}
		x.hours += a.hours(r)
		if activeAt(r, a.q.Now) {
			x.active++
		}
		if a.started(r) {
			x.imps++
		}
		if j, seen := x.latest[r.Prefix]; !seen || !a.imps[j].Start.After(r.Start) {
			x.latest[r.Prefix] = i
			v := r.VolumeMbps
			if v == 0 {
				v = a.info[r.Prefix].VolumeMbps
			}
			x.vol[r.Prefix] = v
		}
	}
	rows := make([]ExchangeRow, 0, len(by))
	for peer, x := range by {
		if a.q.Provider != "" && peer != a.q.Provider {
			continue
		}
		row := ExchangeRow{Exchange: a.q.Exchanges[peer], Peer: peer, Improvements: x.imps, Active: x.active, Prefixes: len(x.vol), SteeredHours: round(x.hours)}
		for _, v := range x.vol {
			row.VolumeMbps += v
		}
		row.VolumeMbps = round(row.VolumeMbps)
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(x, y ExchangeRow) int {
		if c := cmp.Compare(x.Exchange, y.Exchange); c != 0 {
			return c
		}
		return cmp.Compare(x.Peer, y.Peer)
	})
	rep.Rows = rows
	for _, r := range rows {
		rep.lines = append(rep.lines, []string{r.Exchange, r.Peer, strconv.Itoa(r.Improvements), strconv.Itoa(r.Active), strconv.Itoa(r.Prefixes),
			f(r.VolumeMbps), f(r.SteeredHours)})
	}
}
