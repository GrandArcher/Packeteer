package configedit

import (
	"fmt"
	"slices"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/linkout"
)

// pluginKeys are the config keys each plugin type of a settings block reads,
// by "<yaml place>/<type>": need must be set, may is optional. The plugin
// decodes its config strictly, so a key of another type would only fail at
// the start; the form refuses it here with the field it names.
var pluginKeys = map[string]struct{ need, may []string }{
	"rpki.sources/rtr":                    {[]string{"address"}, []string{"refresh", "staleness", "timeout"}},
	"rpki.sources/json":                   {[]string{"url"}, []string{"refresh", "staleness", "timeout"}},
	"rpki.only_invalid.hijack_feeds/file": {[]string{"path"}, nil},
	"registry.sources/peeringdb":          {nil, []string{"base_url", "timeout"}},
	"registry.sources/ripe":               {nil, []string{"base_url", "source", "timeout"}},
	"preflight.router_check/frr":          {[]string{"socket_env"}, nil},
	"preflight.router_check/bird":         {[]string{"socket_env"}, []string{"config_env"}},
	"preflight.router_check/routeros":     {[]string{"url", "username_env", "password_env"}, []string{"ca_file"}},
}

// configKeys are the config.* fields a block's plugin entry offers.
func configKeys(v Values) []string {
	var out []string
	for k := range v {
		if strings.HasPrefix(k, "config.") {
			out = append(out, strings.TrimPrefix(k, "config."))
		}
	}
	slices.Sort(out)
	return out
}

// checkPluginEntry checks one plugin entry (a row, or the router check) of
// place: every config key it sets belongs to its type, and every key the type
// needs is set.
func checkPluginEntry(at, place string, v Values) error {
	typ, _ := v["type"].(string)
	keys, ok := pluginKeys[place+"/"+typ]
	if !ok {
		return nil
	}
	for _, k := range configKeys(v) {
		if s, _ := v["config."+k].(string); s != "" && !slices.Contains(keys.need, k) && !slices.Contains(keys.may, k) {
			return fieldErr(at+".config."+k, "is not a setting of the %s type", typ)
		}
	}
	for _, k := range keys.need {
		if s, _ := v["config."+k].(string); s == "" {
			return fieldErr(at+".config."+k, "is required for the %s type", typ)
		}
	}
	return nil
}

// rowsCheck checks every plugin entry of the rows field key of a block.
func rowsCheck(path, place, key string) func(Values) error {
	return func(v Values) error {
		rows, _ := v[key].([]Values)
		for i, row := range rows {
			if err := checkPluginEntry(fmt.Sprintf("%s.%s[%d]", path, key, i), place, row); err != nil {
				return err
			}
		}
		return nil
	}
}

func checkRouterCheck(v Values) error {
	return checkPluginEntry("preflight.router_check", "preflight.router_check", v)
}

func checkLinkouts(v Values) error {
	if rows, _ := v["custom"].([]Values); len(rows) > linkout.MaxCustom {
		return fieldErr("linkouts.custom", "at most %d entries", linkout.MaxCustom)
	}
	return nil
}
