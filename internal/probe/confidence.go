package probe

import (
	"fmt"
	"strings"
	"time"
)

// Confidence levels.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
	// ConfidenceNone is a result with no measurement (probe error).
	ConfidenceNone = "none"
)

// Passive agreement states on a Confidence.
const (
	PassiveAgree    = "agree"
	PassiveDisagree = "disagree"
)

// Confidence rates how far one sample's loss and RTT can be trusted (#202).
// Routers rate-limit and deprioritize ICMP, so a ping reply is weaker
// evidence than a TCP or UDP reply, a traceroute hop is weaker than the
// destination, few replies are weaker than many, and a wide RTT spread is
// weaker than a tight one. Passive TCP evidence from a span or flow source
// that agrees with the sample stands in for a TCP or UDP reply. It is
// derived from the sample; it changes no decision unless
// thresholds.require_evidence is on.
type Confidence struct {
	Level string  `json:"level"`
	Score float64 `json:"score"`
	// Protocol is the type of the prober that produced the sample: icmp,
	// tcp, udp, another configured type, or federation for a path a peer
	// POP measured with a prober of unknown type. Empty for a failed
	// sample.
	Protocol string `json:"protocol,omitempty"`
	Replies  int    `json:"replies"`
	Sent     int    `json:"sent"`
	// Indirect is set when the sample is this provider's traceroute hop
	// toward the prefix, not an address inside it (#123).
	Indirect bool `json:"indirect,omitempty"`
	// WideSpread is set when the RTT spread (slowest reply minus fastest)
	// is over probe.dispersion_ms, or over the mean RTT when that is not
	// set. It needs two replies.
	WideSpread bool `json:"wide_spread,omitempty"`
	// Passive is agree or disagree when a span or flow source observed
	// TCP traffic toward the prefix on the path that carries it and that
	// traffic does or does not show the same loss state; empty otherwise.
	Passive string `json:"passive,omitempty"`
}

// Confidence score factors. Each weakness halves the score; the level
// bands are documented in CONFIG.md.
const (
	confidenceHighMin   = 0.75
	confidenceMediumMin = 0.4
	weakFactor          = 0.5
)

// RateConfidence builds the Confidence of a stored result. protocol is the
// type of the prober that produced it; dispersion is probe.dispersion_ms
// (0 when off).
func RateConfidence(r Result, protocol string, dispersion time.Duration) Confidence {
	if !r.OK() {
		return Confidence{Level: ConfidenceNone}
	}
	st := r.Stats
	c := Confidence{Protocol: protocol, Replies: st.Received, Sent: st.Sent, Indirect: r.Indirect}
	if st.Received >= 2 {
		spread := st.RTTMax - st.RTTMin
		limit := dispersion
		if limit <= 0 {
			limit = st.RTTAvg
		}
		c.WideSpread = spread > limit
	}
	return c.rated()
}

// rated returns c with Score and Level derived from its facts.
func (c Confidence) rated() Confidence {
	score := 1.0
	if !c.BeyondICMP() {
		score *= weakFactor
	}
	switch {
	case c.Replies == 0:
		score *= weakFactor * weakFactor
	case c.Replies == 1:
		score *= weakFactor
	case c.Replies == 2:
		score *= 0.75
	}
	if c.Indirect {
		score *= weakFactor
	}
	if c.WideSpread {
		score *= weakFactor
	}
	if c.Passive == PassiveDisagree {
		score *= weakFactor
	}
	c.Score = score
	switch {
	case score >= confidenceHighMin:
		c.Level = ConfidenceHigh
	case score >= confidenceMediumMin:
		c.Level = ConfidenceMedium
	default:
		c.Level = ConfidenceLow
	}
	return c
}

// WithPassive returns c with the passive agreement set and re-rated. The
// decision engine calls it for the provider that carries the prefix's
// traffic, the only path passive TCP evidence says anything about.
func (c Confidence) WithPassive(agree bool) Confidence {
	if c.Level == ConfidenceNone {
		return c
	}
	c.Passive = PassiveDisagree
	if agree {
		c.Passive = PassiveAgree
	}
	return c.rated()
}

// BeyondICMP reports whether the sample rests on more than ICMP: a reply to
// the tcp, udp, or https prober, or passive TCP evidence that agrees with it. An
// exec or other prober type is not known to be more than ICMP.
func (c Confidence) BeyondICMP() bool {
	return c.Protocol == "tcp" || c.Protocol == "udp" || c.Protocol == "https" || c.Passive == PassiveAgree
}

// String is the evidence in words, for decision explanations.
func (c Confidence) String() string {
	if c.Level == ConfidenceNone {
		return "no measurement"
	}
	proto := c.Protocol
	if proto == "" {
		proto = "unknown prober"
	}
	parts := []string{proto, fmt.Sprintf("%d/%d replies", c.Replies, c.Sent)}
	if c.Indirect {
		parts = append(parts, "traceroute hop")
	}
	if c.WideSpread {
		parts = append(parts, "wide spread")
	}
	if c.Passive != "" {
		parts = append(parts, "passive "+c.Passive+"s")
	}
	return strings.Join(parts, ", ")
}
