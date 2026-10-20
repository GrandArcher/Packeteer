package httpapi

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/history"
)

var (
	tagParagraph = regexp.MustCompile(`(?s)<p class="tag">(.*?)</p>`)
	disclaimer   = regexp.MustCompile(`(?i)announce|read-only|only reads|display only|changes nothing|changes no routing`)
)

// #351: the global mode banner carries the safety line. A page may add one
// short disclaimer of its own, not one in every paragraph.
func TestPagesCarryOneDisclaimer(t *testing.T) {
	entries, err := fs.ReadDir(webFS, "web")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		n := 0
		for _, m := range tagParagraph.FindAllStringSubmatch(mustWeb(t, "web/"+e.Name()), -1) {
			if disclaimer.MatchString(m[1]) {
				n++
				if len(m[1]) > 400 {
					t.Errorf("%s: a disclaimer paragraph of %d bytes is not short", e.Name(), len(m[1]))
				}
			}
		}
		if n > 1 {
			t.Errorf("%s has %d disclaimer paragraphs, want at most 1", e.Name(), n)
		}
	}
}

// #351: labels people read use plain words; the config key is a tooltip.
func TestNoJargonLabels(t *testing.T) {
	banned := []string{"Score gain", "score gain", "Native exit", "(max_improvements)", "(cc_disable)", "Improvement cap",
		"Loss threshold", "Latency threshold", "RTT threshold", "Probe source", `"in RIB"`, `"not in RIB"`}
	entries, err := fs.ReadDir(webFS, "web")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".html") && !strings.HasSuffix(e.Name(), ".js") {
			continue
		}
		body := mustWeb(t, "web/"+e.Name())
		for _, b := range banned {
			if strings.Contains(body, b) {
				t.Errorf("%s still shows %q", e.Name(), b)
			}
		}
	}
	settings := mustWeb(t, "web/settings.html")
	for _, want := range []string{
		`title="max_improvements">Max simultaneous moves<`,
		`title="thresholds.min_loss_delta_pct">Loss improvement<`,
		`title="thresholds.min_rtt_delta_ms">Latency improvement<`,
	} {
		if !strings.Contains(settings, want) {
			t.Errorf("settings.html lacks %s", want)
		}
	}
}

// #351: the raw API links moved from the Overview footer to the System page.
func TestAPIFooterIsOnSystemPage(t *testing.T) {
	if strings.Contains(mustWeb(t, "web/index.html"), "<footer") {
		t.Error("the Overview still has the API footer")
	}
	sys := mustWeb(t, "web/system.html")
	for _, link := range []string{`href="/api/overview"`, `href="/metrics"`, `href="/api/reports"`} {
		if !strings.Contains(sys, link) {
			t.Errorf("system.html lacks %s", link)
		}
	}
}

// #351: every report the API serves has a title-case name in the page.
func TestReportTitlesCoverEveryReport(t *testing.T) {
	shell := mustWeb(t, "web/shell.js")
	block := regexp.MustCompile(`(?s)var REPORT_TITLES = \{(.*?)\};`).FindStringSubmatch(shell)
	if block == nil {
		t.Fatal("shell.js has no REPORT_TITLES")
	}
	for _, name := range []string{
		history.ReportSummary, history.ReportImprovements, history.ReportCauses, history.ReportPerformance,
		history.ReportTimeSeries, history.ReportProviders, history.ReportPrefixes, history.ReportASNs,
		history.ReportCountries, history.ReportProbes, history.ReportSavings, history.ReportMitigations,
		history.ReportAnomalies, history.ReportExchanges,
	} {
		m := regexp.MustCompile(`\b` + name + `: "([^"]+)"`).FindStringSubmatch(block[1])
		if m == nil {
			t.Errorf("report %s has no title", name)
		} else if m[1][0] < 'A' || m[1][0] > 'Z' {
			t.Errorf("report %s title %q is not capitalised", name, m[1])
		}
	}
}

// #351: a hint about something the config editor can change names the
// Settings anchor, and that anchor exists on the page.
func TestSetupHintsPointAtSettingsAnchors(t *testing.T) {
	settings := mustWeb(t, "web/settings.html")
	for _, fix := range []string{FixBGP, FixProviders, FixTargets, FixPlugins} {
		id := strings.TrimPrefix(fix, "/settings.html#")
		if !strings.Contains(settings, `id="`+id+`"`) {
			t.Errorf("%s: settings.html has no id %q", fix, id)
		}
	}
	o := Overview{Started: true, BGP: OverviewBGP{Configured: true, Peers: 1}, Counts: OverviewCounts{Providers: 1}}
	byID := map[string]Hint{}
	for _, h := range setupHints(o) {
		byID[h.ID] = h
	}
	if h := byID["bgp-down"]; h.Fix != FixBGP || strings.Contains(h.Detail, "mounted") {
		t.Errorf("bgp-down = %+v", h)
	}
	if h := byID["sources"]; h.Fix != FixTargets || strings.Contains(h.Detail, "mounted") || strings.Contains(h.Detail, "Restart") {
		t.Errorf("sources = %+v", h)
	}
	if h := byID["history"]; h.Fix != FixPlugins {
		t.Errorf("history = %+v", h)
	}
	if h := byID["first-round"]; h.Fix != "" {
		t.Errorf("a hint with nothing to edit has a fix: %+v", h)
	}
}

// #351: the server and the browser each word the BGP handshake states; the
// two lists must name the same states.
func TestBGPConnectingMatchesShell(t *testing.T) {
	m := regexp.MustCompile(`var BGP_CONNECTING = \{([^}]*)\}`).FindStringSubmatch(mustWeb(t, "web/shell.js"))
	if m == nil {
		t.Fatal("shell.js has no BGP_CONNECTING")
	}
	js := map[string]bool{}
	for _, k := range regexp.MustCompile(`(\w+):`).FindAllStringSubmatch(m[1], -1) {
		js[strings.ToUpper(k[1])] = true
	}
	if len(js) != len(bgpConnecting) {
		t.Errorf("shell.js has %v, system.go has %v", js, bgpConnecting)
	}
	for s := range bgpConnecting {
		if !js[s] {
			t.Errorf("system.go treats %s as connecting, shell.js does not", s)
		}
	}
}
