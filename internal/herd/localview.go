package herd

import "github.com/GrandArcher/Packeteer/internal/config"

// members matches a member by identity (ASN), node key id, or pull API
// endpoint.
type members struct {
	asns map[uint32]bool
	keys map[string]bool
	urls map[string]bool
}

func newMembers(m config.HerdMembers) members {
	s := members{asns: map[uint32]bool{}, keys: map[string]bool{}, urls: map[string]bool{}}
	for _, a := range m.ASNs {
		s.asns[a] = true
	}
	for _, k := range m.Keys {
		s.keys[k] = true
	}
	for _, u := range m.Endpoints {
		s.urls[u] = true
	}
	return s
}

// has reports whether the member is listed. asn is 0 while it is not
// known yet.
func (s members) has(asn uint32, id, url string) bool {
	return (asn != 0 && s.asns[asn]) || s.keys[id] || s.urls[url]
}

// localView is this node's block and down-weight lists (#686). It changes
// only what this node pulls, shows, and counts; nothing about it is sent
// to another member.
type localView struct {
	block, down members
}

func newLocalView(c *config.Herd) localView {
	return localView{block: newMembers(c.Block), down: newMembers(c.DownWeight)}
}
