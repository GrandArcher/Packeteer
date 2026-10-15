package httpapi

import (
	"regexp"
	"strings"
	"testing"
)

// TestSettingsGuidedInputs checks the settings page (#329) no longer asks
// the operator to type a list, a Go duration, or a config key, and that
// the country list and the validators the widgets use are on the page.
func TestSettingsGuidedInputs(t *testing.T) {
	html := mustWeb(t, "web/settings.html")
	js := mustWeb(t, "web/settings.js")
	countries := mustWeb(t, "web/countries.js")
	countriesAt := strings.Index(html, `src="/countries.js"`)
	settingsAt := strings.Index(html, `src="/settings.js"`)
	commitAt := strings.Index(html, `src="/commitsetup.js"`)
	if countriesAt < 0 || countriesAt > settingsAt || settingsAt > commitAt {
		t.Fatal("countries.js must load before settings.js, which must load before commitsetup.js")
	}
	for _, w := range []string{
		`id="fm-hold-unit"`, `id="fm-floor-rtt-unit"`, `id="in-perf-loss-on"`, `id="in-perf-latency-on"`,
		`id="in-prefix-box"`, `id="wz-asn-err"`, `id="wz-flow-port" type="number"`, `placeholder="15"`, `placeholder="50"`,
	} {
		if !strings.Contains(html, w) {
			t.Errorf("settings.html missing %q", w)
		}
	}
	for _, gone := range []string{"min loss delta", "min RTT delta", "0 (off)", "Separate LANs", "comma separated"} {
		if strings.Contains(html, gone) || strings.Contains(js, gone) {
			t.Errorf("guided form still asks the operator to type %q", gone)
		}
	}
	for _, w := range []string{
		"function validateGuided", "editor-section", "function checkCIDR", "function readDur",
		"function bindCountries", "function bindListens", "function bindDuration", "function bindNames", "isoCountries",
		"g-cidr-input", "Enter an absolute path.", "geoip_db:", "countries: [US]",
		"Loss and latency cannot both be off.", "is refused. Use 2 or more",
	} {
		if !strings.Contains(js, w) {
			t.Errorf("settings.js missing %q", w)
		}
	}
	// Apply must not blur the wizard. Those fields are empty until the operator gets there.
	if i := strings.Index(js, "function validateGuided"); i < 0 {
		t.Fatal("validateGuided missing")
	} else if body := js[i:]; !strings.Contains(body[:strings.Index(body, "\nfunction ")], "editor-section") {
		t.Fatal("validateGuided blurs the whole page")
	}
	codes := regexp.MustCompile(`\["([A-Z]{2})", "([^"]+)"\]`).FindAllStringSubmatch(countries, -1)
	if len(codes) < 240 {
		t.Fatalf("country list has %d codes", len(codes))
	}
	have := map[string]string{}
	for _, m := range codes {
		have[m[1]] = m[2]
	}
	for _, code := range []string{"US", "DE", "FR", "JP"} {
		if have[code] == "" {
			t.Errorf("country list missing %s", code)
		}
	}
	if _, ok := have["XK"]; ok {
		t.Fatal("country list includes XK, which is not an assigned alpha-2 code in this set")
	}
	if strings.Contains(countries, "http://") || strings.Contains(countries, "https://") {
		t.Fatal("country list links off the page")
	}
}
