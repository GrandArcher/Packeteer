package birdseye

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// reasonCommunity is the middle part of IXP Manager's filter tag
// rs-asn:1101:x. The route server keeps a tagged route and does not
// export it.
const reasonCommunity = 1101

// The only Birdseye paths this plugin requests, all with GET.
const (
	pathStatus    = "/api/status"
	pathProtocols = "/api/protocols/bgp"
)

func pathCount(protocol string) string {
	return "/api/routes/count/protocol/" + url.PathEscape(protocol)
}

func pathFiltered(protocol string, asn uint32) string {
	return fmt.Sprintf("/api/routes/lc-zwild/protocol/%s/%d/%d", url.PathEscape(protocol), asn, reasonCommunity)
}

// get fetches base+path with GET and decodes the JSON body into dst. The
// body is capped at maxBytes; a larger body is an error, not a partial read.
func (w *Watch) get(ctx context.Context, base, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return errors.New("bad url")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "packeteer")
	resp, err := w.http.Do(req)
	if err != nil {
		if errors.Is(err, errNoRedirect) {
			return errors.New("redirects are not followed")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("request failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, w.maxBytes+1))
	if err != nil {
		return errors.New("read failed")
	}
	if int64(len(body)) > w.maxBytes {
		return fmt.Errorf("response larger than %d bytes", w.maxBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return errors.New("response is not the expected JSON")
	}
	return nil
}

type statusDoc struct {
	API struct {
		MaxRoutes int `json:"max_routes"`
	} `json:"api"`
	Status struct {
		Version    string `json:"version"`
		RouterID   string `json:"router_id"`
		LastReconf string `json:"last_reconfig"`
		Message    string `json:"message"`
	} `json:"status"`
}

// protocol is one BGP protocol from api/protocols/bgp. Birdseye's name key
// is the BIRD protocol name.
type protocol struct {
	Name            string
	State           string `json:"state"`
	Connection      string `json:"connection"`
	BGPState        string `json:"bgp_state"`
	NeighborAddress string `json:"neighbor_address"`
	NeighborAS      uint32 `json:"neighbor_as"`
	Description     string `json:"description"`
	ImportLimit     int    `json:"import_limit"`
}

// established is true when BIRD reports the BGP state Established.
func (p protocol) established() bool {
	if p.BGPState != "" {
		return strings.EqualFold(p.BGPState, "Established")
	}
	return strings.HasPrefix(strings.ToLower(p.Connection), "established")
}

// stateText is the BGP state, else BIRD's protocol state.
func (p protocol) stateText() string {
	if p.BGPState != "" {
		return p.BGPState
	}
	if f := strings.Fields(p.Connection); len(f) > 0 {
		return f[0]
	}
	return p.State
}

// decodeProtocols decodes api/protocols/bgp, sorted by name. PHP encodes an
// empty array as [], which is no protocols.
func decodeProtocols(raw json.RawMessage) ([]protocol, error) {
	if len(raw) == 0 || string(raw) == "[]" || string(raw) == "null" {
		return nil, nil
	}
	var m map[string]protocol
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, errors.New("protocols are not the expected JSON")
	}
	out := make([]protocol, 0, len(m))
	for name, p := range m {
		p.Name = name
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (w *Watch) protocols(ctx context.Context, base string) ([]protocol, error) {
	var doc struct {
		Protocols json.RawMessage `json:"protocols"`
	}
	if err := w.get(ctx, base, pathProtocols, &doc); err != nil {
		return nil, err
	}
	return decodeProtocols(doc.Protocols)
}

func (w *Watch) status(ctx context.Context, base string) (statusDoc, error) {
	var doc statusDoc
	err := w.get(ctx, base, pathStatus, &doc)
	return doc, err
}

// routeCount reads the route count of one protocol.
func (w *Watch) routeCount(ctx context.Context, base, protocol string) (int, error) {
	var doc struct {
		Count struct {
			Routes *int `json:"routes"`
		} `json:"count"`
	}
	if err := w.get(ctx, base, pathCount(protocol), &doc); err != nil {
		return 0, err
	}
	if doc.Count.Routes == nil || *doc.Count.Routes < 0 {
		return 0, errors.New("route count is missing")
	}
	return *doc.Count.Routes, nil
}

// filtered reads the routes of one protocol that carry rs-asn:1101:x. It
// returns the number of routes with at least one such tag and the count of
// each x. Birdseye caps a route listing at its api.max_routes (maxRoutes,
// zero when it did not say). A listing that reaches the cap may be cut
// short, so it is an error rather than an undercount.
func (w *Watch) filtered(ctx context.Context, base, protocol string, asn uint32, maxRoutes int) (int, map[int]int, error) {
	var doc struct {
		Routes []struct {
			BGP struct {
				Large [][3]uint64 `json:"large_communities"`
			} `json:"bgp"`
		} `json:"routes"`
	}
	if err := w.get(ctx, base, pathFiltered(protocol, asn), &doc); err != nil {
		return 0, nil, err
	}
	if maxRoutes > 0 && len(doc.Routes) >= maxRoutes {
		return 0, nil, fmt.Errorf("route listing reached Birdseye api.max_routes (%d)", maxRoutes)
	}
	routes := 0
	reasons := map[int]int{}
	for _, r := range doc.Routes {
		tagged := false
		seen := map[uint64]bool{}
		for _, c := range r.BGP.Large {
			if c[0] != uint64(asn) || c[1] != reasonCommunity || seen[c[2]] {
				continue
			}
			seen[c[2]] = true
			tagged = true
			if _, ok := reasons[int(c[2])]; ok || len(reasons) < maxReasons {
				reasons[int(c[2])]++
			}
		}
		if tagged {
			routes++
		}
	}
	return routes, reasons, nil
}
