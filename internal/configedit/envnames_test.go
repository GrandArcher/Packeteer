package configedit

import (
	"reflect"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Every place in envPrefixes is a registered plugin type under its list,
// or a typed config block with a *_env field, so a renamed plugin cannot
// leave its secrets without a prefix.
func TestEnvPrefixPlacesExist(t *testing.T) {
	has := map[string]func(string) bool{
		"telemetry":          plugin.Telemetries.Has,
		"exporters":          plugin.Exporters.Has,
		"notifiers":          plugin.Notifiers.Has,
		"auth.sso":           plugin.SSOs.Has,
		"threat_feeds.feeds": plugin.ThreatFeeds.Has,
	}
	for place, prefixes := range envPrefixes {
		if len(prefixes) == 0 {
			t.Errorf("%s: no prefix", place)
		}
		list, typ, ok := strings.Cut(place, "/")
		if !ok {
			if !typedEnvBlock(place) {
				t.Errorf("%s: not a typed block with a *_env field", place)
			}
			continue
		}
		if f := has[list]; f == nil || !f(typ) {
			t.Errorf("%s: %s is not a registered %s plugin", place, typ, list)
		}
	}
}

// typedEnvBlock reports whether the top-level config key block is a struct
// with a string field tagged *_env.
func typedEnvBlock(block string) bool {
	ct := reflect.TypeFor[config.Config]()
	for i := range ct.NumField() {
		f := ct.Field(i)
		if name, _, _ := strings.Cut(f.Tag.Get("yaml"), ","); name != block {
			continue
		}
		bt := f.Type
		if bt.Kind() == reflect.Pointer {
			bt = bt.Elem()
		}
		if bt.Kind() != reflect.Struct {
			return false
		}
		for j := range bt.NumField() {
			g := bt.Field(j)
			if name, _, _ := strings.Cut(g.Tag.Get("yaml"), ","); strings.HasSuffix(name, "_env") && g.Type.Kind() == reflect.String {
				return true
			}
		}
	}
	return false
}

func TestEnvNameAllowed(t *testing.T) {
	for _, c := range []struct {
		place, name string
		want        bool
	}{
		{"telemetry/snmp", "PACKETEER_SNMP_COMMUNITY", true},
		{"telemetry/snmp", "PACKETEER_SNMP_", false},
		{"telemetry/snmp", "PACKETEER_ADMIN_PASSWORD", false},
		{"telemetry/snmp", "PACKETEER_TRAP_COMMUNITY", false},
		{"notifiers/snmptrap", "PACKETEER_TRAP_COMMUNITY", true},
		{"auth.sso/oidc", "PACKETEER_OIDC_CLIENT_SECRET", true},
		{"notifiers/smtp", "PACKETEER_OIDC_CLIENT_SECRET", false},
		{"probers/icmp", "PACKETEER_SNMP_COMMUNITY", false},
	} {
		if got := EnvNameAllowed(c.place, c.name); got != c.want {
			t.Errorf("EnvNameAllowed(%s, %s) = %v, want %v", c.place, c.name, got, c.want)
		}
	}
}
