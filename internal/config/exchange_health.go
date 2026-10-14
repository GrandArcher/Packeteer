package config

import (
	"fmt"
	"time"
)

// Exchange health defaults and bounds (#149).
const (
	DefaultExchangeHealthLossPct = 50
	DefaultExchangeHealthMinPeer = 3
	DefaultExchangeHealthWindow  = 5 * time.Minute
	MaxExchangeHealthWindow      = 24 * time.Hour
	MaxExchangeHealthRTTMS       = 60000
)

// ExchangeHealth tunes the LAN health check of one exchange (#149). Each
// probe round every peer's next hop is probed from that peer's source_ip,
// inside probe.rate_limit_pps, and exchange.degraded is raised when
// enough peers degrade inside the window. Measurement only: nothing is
// announced, withdrawn, or steered from it.
type ExchangeHealth struct {
	// Enabled is true when omitted. false stops the next-hop probes.
	Enabled *bool `yaml:"enabled"`
	// LossPct is the loss at or above which a peer is degraded. A next
	// hop that answers nothing is always degraded.
	LossPct float64 `yaml:"loss_pct"`
	// RTTMS, when positive, also degrades a peer whose mean RTT is above
	// it. Zero judges loss only.
	RTTMS int `yaml:"rtt_ms"`
	// MinPeers is how many peers must be degraded for the exchange to
	// be. An exchange with fewer peers never raises the alert.
	MinPeers int `yaml:"min_peers"`
	// MinPercent, when positive, also raises the alert when that share of
	// the exchange's peers is degraded.
	MinPercent int `yaml:"min_percent"`
	// Window is how long a peer counts as degraded after its last
	// degraded probe, which is also how long the alert holds after the
	// peers recover.
	Window time.Duration `yaml:"window"`
}

// On reports whether the next-hop probes run.
func (h ExchangeHealth) On() bool { return h.Enabled == nil || *h.Enabled }

func (c *Config) defaultExchangeHealth() {
	for i := range c.Exchanges {
		h := &c.Exchanges[i].Health
		if h.LossPct == 0 {
			h.LossPct = DefaultExchangeHealthLossPct
		}
		if h.MinPeers == 0 {
			h.MinPeers = DefaultExchangeHealthMinPeer
		}
		if h.Window == 0 {
			h.Window = DefaultExchangeHealthWindow
		}
	}
}

func (c *Config) validateExchangeHealth(add func(string, ...any)) {
	for i, ex := range c.Exchanges {
		h, label := ex.Health, fmt.Sprintf("exchanges[%d] (%s): health", i, ex.Name)
		if h.LossPct <= 0 || h.LossPct > 100 {
			add("%s.loss_pct %v must be above 0 and at most 100", label, h.LossPct)
		}
		if h.RTTMS < 0 || h.RTTMS > MaxExchangeHealthRTTMS {
			add("%s.rtt_ms %d must be between 0 and %d", label, h.RTTMS, MaxExchangeHealthRTTMS)
		}
		if h.MinPeers < 2 {
			add("%s.min_peers %d must be at least 2: one degraded peer is that member, not the exchange", label, h.MinPeers)
		}
		if h.MinPercent < 0 || h.MinPercent > 100 {
			add("%s.min_percent %d must be between 0 and 100", label, h.MinPercent)
		}
		if h.Window < c.Probe.Interval || h.Window > MaxExchangeHealthWindow {
			add("%s.window %s must be between probe.interval (%s) and %s", label, h.Window, c.Probe.Interval, MaxExchangeHealthWindow)
		}
	}
}
