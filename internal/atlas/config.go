package atlas

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// KeyEnv is the environment variable that holds the operator's RIPE Atlas
// API key. The key is never read from the config file.
const KeyEnv = "PACKETEER_ATLAS_API_KEY"

// DefaultBase is the RIPE Atlas REST API. It repeats outside.DefaultAtlasURL
// on purpose: a test keeps internal/outside out of every package but the
// daemon and the ops API, and this one is read with a key.
const DefaultBase = "https://atlas.ripe.net/api/v2"

// Defaults and bounds for the atlas block.
const (
	DefaultProbes                 = 3
	MaxProbes                     = 10
	DefaultAfterMoveDelay         = 3 * time.Minute
	MinAfterMoveDelay             = time.Minute
	MaxAfterMoveDelay             = time.Hour
	DefaultMaxCreditsPerDay       = 500
	MaxMaxCreditsPerDay           = 100000
	DefaultMaxMeasurementsPerHour = 4
	MaxMaxMeasurementsPerHour     = 60
	DefaultSourceType             = "area"
	DefaultSourceValue            = "WW"
	DefaultStateFile              = "/var/lib/packeteer/atlas.json"
)

// Source picks the Atlas probes a measurement runs from.
type Source struct {
	// Type is area, country, or asn.
	Type string `yaml:"type"`
	// Value is an Atlas area (WW, West, North-Central, South-Central,
	// North-East, South-East), a two-letter country code, or an AS number.
	Value string `yaml:"value"`
}

// Config is the atlas block.
type Config struct {
	// Enabled turns the integration on. Off, or with no key in KeyEnv,
	// nothing calls Atlas.
	Enabled bool `yaml:"enabled"`
	// ProbeID is the operator's own hosted probe. When it is connected it
	// is added to every measurement beside the probes Source picks.
	ProbeID int `yaml:"probe_id"`
	// Source picks the other probes (default area WW).
	Source Source `yaml:"source"`
	// Probes is how many probes Source picks per measurement (default 3).
	Probes int `yaml:"probes"`
	// AfterMove measures a destination once after Packeteer announces a
	// move for it. Off by default.
	AfterMove bool `yaml:"after_move"`
	// AfterMoveDelay is how long to wait after the move so the route has
	// propagated (default 3m).
	AfterMoveDelay time.Duration `yaml:"after_move_delay"`
	// MaxCreditsPerDay caps the estimated credits booked in any 24 hours
	// (default 500).
	MaxCreditsPerDay int `yaml:"max_credits_per_day"`
	// MaxMeasurementsPerHour caps measurements created in any hour
	// (default 4).
	MaxMeasurementsPerHour int `yaml:"max_measurements_per_hour"`
	// StateFile keeps the spend ledger and recent results across
	// restarts, so a restart does not reset the caps.
	StateFile string `yaml:"state_file"`

	// BaseURL points tests at a fake Atlas API.
	BaseURL string `yaml:"-"`
}

// WithDefaults fills unset keys.
func (c Config) WithDefaults() Config {
	if c.Source.Type == "" && c.Source.Value == "" {
		c.Source = Source{Type: DefaultSourceType, Value: DefaultSourceValue}
	}
	if c.Probes == 0 {
		c.Probes = DefaultProbes
	}
	if c.AfterMoveDelay == 0 {
		c.AfterMoveDelay = DefaultAfterMoveDelay
	}
	if c.MaxCreditsPerDay == 0 {
		c.MaxCreditsPerDay = DefaultMaxCreditsPerDay
	}
	if c.MaxMeasurementsPerHour == 0 {
		c.MaxMeasurementsPerHour = DefaultMaxMeasurementsPerHour
	}
	if c.StateFile == "" {
		c.StateFile = DefaultStateFile
	}
	if c.BaseURL == "" {
		c.BaseURL = DefaultBase
	}
	return c
}

var (
	areas       = []string{"WW", "West", "North-Central", "South-Central", "North-East", "South-East"}
	countryCode = regexp.MustCompile(`^[A-Z]{2}$`)
)

// Validate reports every problem with the block.
func (c Config) Validate(add func(string, ...any)) {
	if !c.Enabled {
		if c != (Config{}) {
			add("atlas: set enabled: true to use probe_id, source, probes, after_move, state_file, or the caps")
		}
		return
	}
	if c.ProbeID < 0 {
		add("atlas.probe_id: %d is not a probe id", c.ProbeID)
	}
	if c.Probes < 0 || c.Probes > MaxProbes {
		add("atlas.probes: %d is out of range (0 uses %d, at most %d)", c.Probes, DefaultProbes, MaxProbes)
	}
	if c.AfterMoveDelay != 0 && (c.AfterMoveDelay < MinAfterMoveDelay || c.AfterMoveDelay > MaxAfterMoveDelay) {
		add("atlas.after_move_delay: %s is out of range (%s to %s)", c.AfterMoveDelay, MinAfterMoveDelay, MaxAfterMoveDelay)
	}
	if c.MaxCreditsPerDay < 0 || c.MaxCreditsPerDay > MaxMaxCreditsPerDay {
		add("atlas.max_credits_per_day: %d is out of range (0 uses %d, at most %d)", c.MaxCreditsPerDay, DefaultMaxCreditsPerDay, MaxMaxCreditsPerDay)
	}
	if c.MaxMeasurementsPerHour < 0 || c.MaxMeasurementsPerHour > MaxMaxMeasurementsPerHour {
		add("atlas.max_measurements_per_hour: %d is out of range (0 uses %d, at most %d)", c.MaxMeasurementsPerHour, DefaultMaxMeasurementsPerHour, MaxMaxMeasurementsPerHour)
	}
	if c.Source != (Source{}) {
		c.Source.validate(add)
	}
}

func (s Source) validate(add func(string, ...any)) {
	switch s.Type {
	case "area":
		if !slices.Contains(areas, s.Value) {
			add("atlas.source.value: %q is not an area (one of %s)", s.Value, strings.Join(areas, ", "))
		}
	case "country":
		if !countryCode.MatchString(s.Value) {
			add("atlas.source.value: %q is not a two-letter upper-case country code", s.Value)
		}
	case "asn":
		if n, err := strconv.ParseUint(s.Value, 10, 32); err != nil || n == 0 {
			add("atlas.source.value: %q is not an AS number", s.Value)
		}
	default:
		add("atlas.source.type: %q is invalid (want area, country, or asn)", s.Type)
	}
}
