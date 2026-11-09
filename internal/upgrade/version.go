// Package upgrade is the Settings page's version check, one-click
// upgrade, and rollback (#196). It reads GitHub releases, verifies the
// release's signed checksum file and the binary against it, stages the
// binary next to the data volume, and records which version should run.
// It never announces. Switching is done by the controller: it shuts down
// through the same path as SIGTERM (every Packeteer route is withdrawn,
// the HA lease released) and only then starts the chosen binary, which
// begins in the configured mode and learns the RIB before it injects.
package upgrade

import (
	"regexp"
	"strconv"
	"strings"
)

// tagRE is the only shape of release tag the package accepts. It is also
// what makes a tag safe to use in a directory name.
var tagRE = regexp.MustCompile(`^v?([0-9]{1,6})\.([0-9]{1,6})\.([0-9]{1,6})(?:-([0-9A-Za-z][0-9A-Za-z.]{0,30}))?$`)

// Normalize strips a leading "v": release tags are v0.6.0, the binary
// reports 0.6.0.
func Normalize(v string) string { return strings.TrimPrefix(strings.TrimSpace(v), "v") }

// ValidTag reports whether tag is a release tag this package handles.
func ValidTag(tag string) bool { return tagRE.MatchString(tag) }

type semver struct {
	maj, min, pat int
	pre           string
}

func parseSemver(v string) (semver, bool) {
	m := tagRE.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return semver{}, false
	}
	n := func(s string) int { i, _ := strconv.Atoi(s); return i }
	return semver{n(m[1]), n(m[2]), n(m[3]), m[4]}, true
}

// Compare returns -1, 0, or 1 for a < b, a == b, a > b. ok is false when
// either side is not a release version (for example "dev").
func Compare(a, b string) (c int, ok bool) {
	x, okx := parseSemver(a)
	y, oky := parseSemver(b)
	if !okx || !oky {
		return 0, false
	}
	for _, d := range []int{x.maj - y.maj, x.min - y.min, x.pat - y.pat} {
		if d != 0 {
			if d < 0 {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case x.pre == y.pre:
		return 0, true
	case x.pre == "":
		return 1, true
	case y.pre == "":
		return -1, true
	}
	return strings.Compare(x.pre, y.pre), true
}
