package scripts

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A workflow action ref is a mutable tag unless it is a full commit SHA, and
// publish.yml runs with the registry login and contents: write on tag pushes.
var (
	usesLine  = regexp.MustCompile(`(?m)^\s*(?:-\s+)?uses:\s*(\S+)`)
	pinnedRef = regexp.MustCompile(`^[^@\s]+@[0-9a-f]{40}$`)
)

func unpinnedUses(workflow string) []string {
	var bad []string
	for _, m := range usesLine.FindAllStringSubmatch(workflow, -1) {
		ref := m[1]
		if strings.HasPrefix(ref, "./") || pinnedRef.MatchString(ref) {
			continue
		}
		bad = append(bad, ref)
	}
	return bad
}

func TestUnpinnedUsesFlagsTagsAndBranchesButNotShasOrLocalActions(t *testing.T) {
	sha := strings.Repeat("a1", 20)
	for _, tc := range []struct {
		name, body string
		want       []string
	}{
		{"sha with comment", "      - uses: actions/checkout@" + sha + " # v7\n", nil},
		{"named step", "        uses: docker/login-action@" + sha + "\n", nil},
		{"local action", "      - uses: ./.github/actions/x\n", nil},
		{"major tag", "      - uses: actions/checkout@v7\n", []string{"actions/checkout@v7"}},
		{"branch", "        uses: docker/build-push-action@main\n", []string{"docker/build-push-action@main"}},
		{"short sha", "      - uses: a/b@" + sha[:7] + "\n", []string{"a/b@" + sha[:7]}},
		{"uppercase sha", "      - uses: a/b@" + strings.ToUpper(sha) + "\n", []string{"a/b@" + strings.ToUpper(sha)}},
		{"no ref", "      - uses: a/b\n", []string{"a/b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := unpinnedUses(tc.body)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("unpinnedUses = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWorkflowActionsArePinnedByCommitSHA(t *testing.T) {
	var files []string
	for _, pat := range []string{"*.yml", "*.yaml"} {
		m, err := filepath.Glob("../.github/workflows/" + pat)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) == 0 {
		t.Fatal("no workflows found under .github/workflows")
	}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, ref := range unpinnedUses(string(body)) {
			t.Errorf("%s: uses %s is not pinned to a 40-hex commit SHA", filepath.Base(f), ref)
		}
	}
}
