package outside

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Limits on what is read from RIPE Atlas. Only public data is requested,
// without an API key, a few requests per refresh, one at a time.
const (
	// DefaultAtlasURL is the public RIPE Atlas REST API.
	DefaultAtlasURL = "https://atlas.ripe.net/api/v2"
	atlasTimeout    = 20 * time.Second
	atlasMaxBody    = 4 << 20
	// atlasRows caps the rows shown per measurement: the highest loss first.
	atlasRows = 25
)

// AtlasOptions configures Atlas. BaseURL and Client exist so tests can
// point it at a local server.
type AtlasOptions struct {
	BaseURL      string
	Measurements []int
	Probes       []int
	Refresh      time.Duration
	Client       *http.Client
	Log          *slog.Logger
	Now          func() time.Time
}

// Atlas reads public RIPE Atlas ping results and hosted probe status. Run
// refreshes it; Section only returns what the last refresh kept.
type Atlas struct {
	o AtlasOptions

	mu      sync.Mutex
	fetched time.Time
	rows    [][]string
	skipped int
	err     string
}

// NewAtlas fills the defaults.
func NewAtlas(o AtlasOptions) *Atlas {
	if o.BaseURL == "" {
		o.BaseURL = DefaultAtlasURL
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: atlasTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Atlas{o: o}
}

// ID implements Source.
func (*Atlas) ID() string { return "atlas" }

// Run reads Atlas now and then every Refresh until ctx ends. A failed read
// keeps the last good rows and shows the error beside them.
func (a *Atlas) Run(ctx context.Context) {
	t := time.NewTicker(a.o.Refresh)
	defer t.Stop()
	for {
		a.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type atlasResult struct {
	Type      string  `json:"type"`
	MsmID     int     `json:"msm_id"`
	ProbeID   int     `json:"prb_id"`
	Sent      int     `json:"sent"`
	Rcvd      int     `json:"rcvd"`
	Avg       float64 `json:"avg"`
	Timestamp int64   `json:"timestamp"`
}

type atlasProbe struct {
	ID          int    `json:"id"`
	CountryCode string `json:"country_code"`
	IsAnchor    bool   `json:"is_anchor"`
	Status      struct {
		Name  string `json:"name"`
		Since string `json:"since"`
	} `json:"status"`
}

func (a *Atlas) get(ctx context.Context, path string, into any) error {
	ctx, cancel := context.WithTimeout(ctx, atlasTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.o.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "packeteer-herd-dashboard")
	res, err := a.o.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", path, res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, atlasMaxBody+1))
	if err != nil {
		return err
	}
	if len(body) > atlasMaxBody {
		return fmt.Errorf("%s: response over %d bytes", path, atlasMaxBody)
	}
	return json.Unmarshal(body, into)
}

func (a *Atlas) refresh(ctx context.Context) {
	var rows [][]string
	skipped := 0
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	for _, id := range a.o.Measurements {
		var results []atlasResult
		if err := a.get(ctx, "/measurements/"+strconv.Itoa(id)+"/latest/", &results); err != nil {
			note(err)
			continue
		}
		var pings []atlasResult
		for _, r := range results {
			if r.Type == "ping" && r.Sent > 0 {
				pings = append(pings, r)
			} else {
				skipped++
			}
		}
		loss := func(r atlasResult) float64 { return 100 * float64(max(r.Sent-r.Rcvd, 0)) / float64(r.Sent) }
		sort.Slice(pings, func(i, j int) bool {
			if li, lj := loss(pings[i]), loss(pings[j]); li != lj {
				return li > lj
			}
			return pings[i].ProbeID < pings[j].ProbeID
		})
		if len(pings) > atlasRows {
			pings = pings[:atlasRows]
		}
		for _, r := range pings {
			rtt := ""
			if r.Rcvd > 0 {
				rtt = strconv.FormatFloat(r.Avg, 'f', 1, 64)
			}
			rows = append(rows, []string{"mesh measurement " + strconv.Itoa(id) + ", probe " + strconv.Itoa(r.ProbeID),
				"ping", strconv.FormatFloat(loss(r), 'f', 1, 64) + " %", rtt, time.Unix(r.Timestamp, 0).UTC().Format(time.RFC3339)})
		}
	}
	for _, id := range a.o.Probes {
		var p atlasProbe
		if err := a.get(ctx, "/probes/"+strconv.Itoa(id)+"/", &p); err != nil {
			note(err)
			continue
		}
		kind := "own probe " + strconv.Itoa(id)
		if p.IsAnchor {
			kind = "own anchor " + strconv.Itoa(id)
		}
		rows = append(rows, []string{kind + " (" + p.CountryCode + ")", p.Status.Name, "", "", p.Status.Since})
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.err = ""
	if firstErr != nil {
		a.err = firstErr.Error()
		a.o.Log.Warn("herd dashboard: RIPE Atlas read failed", "err", firstErr)
		// Rows already held keep their own age; mixing them with a partial
		// read under a new age would mislabel the old ones.
		if !a.fetched.IsZero() {
			return
		}
	}
	a.fetched, a.rows, a.skipped = a.o.Now(), rows, skipped
}

// Section returns the rows of the last read, labeled with when it was made.
func (a *Atlas) Section(_ Target, now time.Time) Section {
	sec := Section{ID: "atlas", Source: "RIPE Atlas (public data, not filtered by the selected target)",
		Columns: []string{"What", "Type or status", "Loss", "RTT avg (ms)", "Result time or status since (UTC)"}}
	a.mu.Lock()
	defer a.mu.Unlock()
	sec.Rows, sec.Error = a.rows, a.err
	sec.stamp(a.fetched, now)
	switch {
	case a.fetched.IsZero() && a.err == "":
		sec.Note = "Not read yet."
	case a.skipped > 0:
		sec.Note = fmt.Sprintf("%d results of other types are not shown; each measurement lists its %d worst ping rows.", a.skipped, atlasRows)
	}
	return sec
}
