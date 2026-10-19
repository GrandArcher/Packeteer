// Package herd is opt-in sharing of probe measurements between Packeteer
// instances run by different operators (#260, docs/design/herd.md). Each
// member stores its own per-round records, serves them signed over mutual
// TLS pinned to per-node keys, and pulls the records of its static peers.
// Pulled data is shown per vantage and is never merged, never re-served,
// and never read by Decide, a scorer, or the announcer. Herd runs on its
// own goroutines with bounded queues; if it fails or is overloaded the
// controller behaves as if herd were off.
package herd

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"time"
)

// Schema is the record, status, and envelope version. A puller ignores
// records of any other schema.
const Schema = "herd/v1"

// Limits on what a puller accepts in one record, whatever the peer sends.
const (
	maxSamples  = 16384
	maxSent     = 1 << 20
	maxRTTms    = 600000
	maxPathLen  = 128
	maxASPaths  = 64
	maxIDLen    = 64
	maxRoutes   = 1 << 24
	statEpsilon = 1e-6
)

// Sample is one reply. Host numbers the probed host within the record,
// from 0, in send order; no address is carried.
type Sample struct {
	Host  int     `json:"h"`
	RTTMs float64 `json:"rtt_ms"`
}

// Record is one probe round through one provider toward one origin ASN or
// one learned route.
type Record struct {
	Schema      string     `json:"schema"`
	ID          string     `json:"id"`
	Granularity string     `json:"granularity"`
	Prefix      string     `json:"prefix,omitempty"`
	Routes      int        `json:"routes,omitempty"`
	OriginASN   uint32     `json:"origin_asn,omitempty"`
	ProviderASN uint32     `json:"provider_asn,omitempty"`
	ASPath      []uint32   `json:"as_path,omitempty"`
	ASPaths     [][]uint32 `json:"as_paths,omitempty"`
	Vantage     string     `json:"vantage"`
	Method      string     `json:"method"`
	Time        time.Time  `json:"time"`
	Sent        int        `json:"sent"`
	Samples     []Sample   `json:"samples,omitempty"`
	LossPct     *float64   `json:"loss_pct,omitempty"`
	RTTMinMs    *float64   `json:"rtt_min_ms,omitempty"`
	RTTAvgMs    *float64   `json:"rtt_avg_ms,omitempty"`
	RTTMaxMs    *float64   `json:"rtt_max_ms,omitempty"`
	JitterMs    *float64   `json:"jitter_ms,omitempty"`
	Failed      bool       `json:"failed,omitempty"`
}

// Summary is what a record's statistics must equal when recomputed from its
// samples. It follows probe.Compute and combineStats: loss over all packets
// sent, RTT min and max over all replies, the mean weighted by replies, and
// jitter as the mean absolute difference between consecutive replies of the
// same host, pooled over the gaps.
type Summary struct {
	Replies            int
	LossPct            float64
	Min, Avg, Max, Jit float64
}

// Summarize computes the statistics of sent packets and their replies.
func Summarize(sent int, samples []Sample) Summary {
	s := Summary{Replies: len(samples)}
	if sent > 0 {
		lost := max(sent-s.Replies, 0)
		s.LossPct = 100 * float64(lost) / float64(sent)
	}
	if len(samples) == 0 {
		return s
	}
	s.Min, s.Max = samples[0].RTTMs, samples[0].RTTMs
	var sum, diff float64
	gaps := 0
	for i, sm := range samples {
		sum += sm.RTTMs
		s.Min = math.Min(s.Min, sm.RTTMs)
		s.Max = math.Max(s.Max, sm.RTTMs)
		if i > 0 && samples[i-1].Host == sm.Host {
			diff += math.Abs(sm.RTTMs - samples[i-1].RTTMs)
			gaps++
		}
	}
	s.Avg = sum / float64(len(samples))
	if gaps > 0 {
		s.Jit = diff / float64(gaps)
	}
	return s
}

// setSummary fills the statistics of r from its samples.
func (r *Record) setSummary() {
	if r.Failed {
		return
	}
	s := Summarize(r.Sent, r.Samples)
	r.LossPct = &s.LossPct
	if s.Replies == 0 {
		return
	}
	r.RTTMinMs, r.RTTAvgMs, r.RTTMaxMs, r.JitterMs = &s.Min, &s.Avg, &s.Max, &s.Jit
}

func near(p *float64, want float64) bool {
	return p != nil && math.Abs(*p-want) <= statEpsilon
}

// Validate rejects a record that is malformed or whose statistics do not
// match its samples. It does not judge whose numbers are right. granularity
// is the envelope's.
func (r *Record) Validate(granularity string) error {
	switch {
	case r.Schema != Schema:
		return fmt.Errorf("schema %q", r.Schema)
	case r.ID == "" || len(r.ID) > maxIDLen:
		return errors.New("bad id")
	case r.Granularity != granularity:
		return fmt.Errorf("granularity %q is not the envelope's %q", r.Granularity, granularity)
	case len(r.Vantage) != 2 || r.Vantage[0] < 'A' || r.Vantage[0] > 'Z' || r.Vantage[1] < 'A' || r.Vantage[1] > 'Z':
		return fmt.Errorf("vantage %q", r.Vantage)
	case r.Method != "icmp" && r.Method != "tcp" && r.Method != "udp":
		return fmt.Errorf("method %q", r.Method)
	case r.Time.IsZero():
		return errors.New("no time")
	case r.Sent < 0 || r.Sent > maxSent:
		return fmt.Errorf("sent %d", r.Sent)
	}
	switch r.Granularity {
	case "origin_asn":
		if r.Prefix != "" || r.ASPath != nil {
			return errors.New("origin_asn record carries a prefix or as_path")
		}
		if r.OriginASN == 0 || r.Routes < 1 || r.Routes > maxRoutes {
			return errors.New("origin_asn record needs origin_asn and routes")
		}
	case "route":
		p, err := netip.ParsePrefix(r.Prefix)
		if err != nil || p != p.Masked() || !Shareable(p) {
			return fmt.Errorf("prefix %q", r.Prefix)
		}
		if r.Routes != 0 || r.ASPaths != nil {
			return errors.New("route record carries routes or as_paths")
		}
	default:
		return fmt.Errorf("granularity %q", r.Granularity)
	}
	if len(r.ASPath) > maxPathLen || len(r.ASPaths) > maxASPaths {
		return errors.New("as path too long")
	}
	for _, p := range append([][]uint32{r.ASPath}, r.ASPaths...) {
		if len(p) > maxPathLen {
			return errors.New("as path too long")
		}
		for _, a := range p {
			if a == 0 {
				return errors.New("as path has ASN 0")
			}
		}
	}
	if r.Failed {
		if r.Sent != 0 || len(r.Samples) != 0 || r.LossPct != nil || r.RTTMinMs != nil || r.RTTAvgMs != nil || r.RTTMaxMs != nil || r.JitterMs != nil {
			return errors.New("failed record carries a measurement")
		}
		return nil
	}
	if len(r.Samples) > r.Sent || len(r.Samples) > maxSamples {
		return errors.New("more replies than packets sent")
	}
	host := 0
	for i, sm := range r.Samples {
		if math.IsNaN(sm.RTTMs) || sm.RTTMs < 0 || sm.RTTMs > maxRTTms {
			return fmt.Errorf("sample %d rtt %v", i, sm.RTTMs)
		}
		if sm.Host < host || sm.Host > host+1 {
			return fmt.Errorf("sample %d is out of order", i)
		}
		host = sm.Host
	}
	want := Summarize(r.Sent, r.Samples)
	if r.LossPct == nil || *r.LossPct < 0 || *r.LossPct > 100 || !near(r.LossPct, want.LossPct) {
		return errors.New("loss_pct does not match the samples")
	}
	if want.Replies == 0 {
		if r.RTTMinMs != nil || r.RTTAvgMs != nil || r.RTTMaxMs != nil || r.JitterMs != nil {
			return errors.New("rtt statistics without replies")
		}
		return nil
	}
	if !near(r.RTTMinMs, want.Min) || !near(r.RTTAvgMs, want.Avg) || !near(r.RTTMaxMs, want.Max) || !near(r.JitterMs, want.Jit) {
		return errors.New("rtt or jitter does not match the samples")
	}
	return nil
}
