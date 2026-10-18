package httpapi

import (
	"regexp"
	"strings"
	"testing"
)

// TestSettingsGuidedInputs checks the settings page (#329) no longer asks
// the operator to type a list, a Go duration, or a config key, and that the
// country list loads first. TestSettingsFormInputs covers what the widgets do.
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
		`id="in-prefix-box"`, `id="wz-asn-err"`, `id="wz-flow-port" type="number"`,
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
	if strings.Contains(countries, "http://") || strings.Contains(countries, "https://") {
		t.Fatal("country list links off the page")
	}
}
