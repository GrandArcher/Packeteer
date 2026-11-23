package mikrotik

import (
	"strconv"
	"strings"
	"unicode"

	"github.com/GrandArcher/Packeteer/internal/offload"
)

type version struct{ major, minor, patch int }

func (v version) less(o version) bool {
	if v.major != o.major {
		return v.major < o.major
	}
	if v.minor != o.minor {
		return v.minor < o.minor
	}
	return v.patch < o.patch
}

// parseVersion reads "7.24.2", "7.16rc1" or "7.17beta4": digits up to the
// first non-digit in each dotted part. A missing patch is 0. Anything that
// does not start with major.minor is not a version.
func parseVersion(s string) (version, bool) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) < 2 {
		return version{}, false
	}
	var n [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		digits := parts[i]
		if cut := strings.IndexFunc(digits, func(r rune) bool { return !unicode.IsDigit(r) }); cut >= 0 {
			digits = digits[:cut]
		}
		v, err := strconv.Atoi(digits)
		if err != nil {
			if i < 2 {
				return version{}, false
			}
			break
		}
		n[i] = v
	}
	return version{n[0], n[1], n[2]}, true
}

// versionRule is a half-open range [from, to) of RouterOS versions with a
// documented defect. level is the most a profile may do on a version in it.
type versionRule struct {
	label    string
	from, to version
	level    offload.RunLevel
	code     string
	reason   string
}

var versionRules = []versionRule{
	{"<= 7.2", version{}, version{7, 3, 0}, offload.Refuse, CodeVersionRefused, "undefined behavior when the hardware table overflows"},
	{"< 7.10", version{7, 3, 0}, version{7, 10, 0}, offload.Report, CodeVersionReportOnly, "no L3HW monitor to read"},
	{"7.16 - 7.18", version{7, 16, 0}, version{7, 19, 0}, offload.DryRun, CodeVersionWarn, "field reports of BGP lock-ups"},
}

func knownBad() []offload.KnownBad {
	out := make([]offload.KnownBad, len(versionRules))
	for i, r := range versionRules {
		out[i] = offload.KnownBad{Version: r.label, Reason: r.reason}
	}
	return out
}

// ruleFor returns the rule v falls in.
func ruleFor(v version) (versionRule, bool) {
	for _, r := range versionRules {
		if !v.less(r.from) && v.less(r.to) {
			return r, true
		}
	}
	return versionRule{}, false
}
