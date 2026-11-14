package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// edgeCommands are the vtysh commands one sample reads, in one exec so
// the table and the session states come from the same moment.
var edgeCommands = []string{"show bgp ipv4 unicast json", "show bgp neighbors json"}

// Peer is one BGP neighbor as the edge reports it.
type Peer struct {
	State    string
	RemoteAS uint32
	// HoldMs is the negotiated hold time while Established.
	HoldMs int64
	// UpdatesRecv counts UPDATE messages from the peer. FRR keeps the
	// count across session resets, and an UPDATE only arrives on an
	// Established session.
	UpdatesRecv int64
	// GR is true when the peer advertised the graceful-restart capability.
	GR bool
}

// Established reports whether the session is up.
func (p Peer) Established() bool { return p.State == "Established" }

// Sample is one read of the edge.
type Sample struct {
	At time.Time
	// Routes maps each prefix in the table to the peer of each of its
	// paths ("(unspec)" for one the edge originates).
	Routes map[string][]string
	Peers  map[string]Peer
}

// From lists the prefixes the edge holds a path for from peer.
func (s Sample) From(peer string) []string {
	var out []string
	for prefix, peers := range s.Routes {
		for _, p := range peers {
			if p == peer {
				out = append(out, prefix)
				break
			}
		}
	}
	return out
}

// Holds reports whether the edge holds any path from peer.
func (s Sample) Holds(peer string) bool { return len(s.From(peer)) > 0 }

type frrPath struct {
	PeerID string `json:"peerId"`
}

type frrNeighbor struct {
	RemoteAS    uint32 `json:"remoteAs"`
	State       string `json:"bgpState"`
	HoldMs      int64  `json:"bgpTimerHoldTimeMsecs"`
	MessageStat struct {
		UpdatesRecv int64 `json:"updatesRecv"`
	} `json:"messageStats"`
	Capabilities map[string]any `json:"neighborCapabilities"`
	GRInfo       struct {
		RemoteMode string `json:"remoteGrMode"`
	} `json:"gracefulRestartInfo"`
}

// parseSample reads the output of edgeCommands: the unicast table (the
// object with "routes") and the neighbor map, in either order. vtysh may
// print text between them, which is skipped.
func parseSample(out string) (Sample, error) {
	s := Sample{}
	var haveRoutes, havePeers bool
	rest := out
	for {
		i := strings.Index(rest, "{")
		if i < 0 {
			break
		}
		dec := json.NewDecoder(strings.NewReader(rest[i:]))
		var obj map[string]json.RawMessage
		if err := dec.Decode(&obj); err != nil {
			return Sample{}, fmt.Errorf("edge output: %w", err)
		}
		rest = rest[i+int(dec.InputOffset()):]
		if raw, ok := obj["routes"]; ok {
			var routes map[string][]frrPath
			if err := json.Unmarshal(raw, &routes); err != nil {
				return Sample{}, fmt.Errorf("edge routes: %w", err)
			}
			s.Routes = map[string][]string{}
			for prefix, paths := range routes {
				for _, p := range paths {
					s.Routes[prefix] = append(s.Routes[prefix], p.PeerID)
				}
			}
			haveRoutes = true
			continue
		}
		s.Peers = map[string]Peer{}
		for addr, raw := range obj {
			if _, err := netip.ParseAddr(addr); err != nil {
				continue
			}
			var n frrNeighbor
			if err := json.Unmarshal(raw, &n); err != nil {
				return Sample{}, fmt.Errorf("edge neighbor %s: %w", addr, err)
			}
			s.Peers[addr] = Peer{
				State:       n.State,
				RemoteAS:    n.RemoteAS,
				HoldMs:      n.HoldMs,
				UpdatesRecv: n.MessageStat.UpdatesRecv,
				GR:          grReceived(n),
			}
		}
		havePeers = true
	}
	if !haveRoutes || !havePeers {
		return Sample{}, fmt.Errorf("edge output has no table (%v) or no neighbors (%v)", haveRoutes, havePeers)
	}
	return s, nil
}

// grReceived reads both places FRR reports a peer's graceful-restart
// capability: a neighborCapabilities key starting with gracefulRestart
// whose value says "received", and the remote GR mode.
func grReceived(n frrNeighbor) bool {
	for k, v := range n.Capabilities {
		if strings.HasPrefix(k, "gracefulRestart") && strings.Contains(strings.ToLower(fmt.Sprint(v)), "received") {
			return true
		}
	}
	return n.GRInfo.RemoteMode == "Restart" || n.GRInfo.RemoteMode == "Helper"
}
