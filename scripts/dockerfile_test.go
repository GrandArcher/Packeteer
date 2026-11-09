package scripts

import (
	"os"
	"regexp"
	"testing"

	"gopkg.in/yaml.v3"
)

// The image builder is pinned by digest so a build is repeatable, which also
// freezes the Go patch release and its standard-library fixes. Dependabot's
// docker entry is what moves the digest; these tests fail if either half goes.

var (
	builderFrom = regexp.MustCompile(`(?m)^FROM --platform=\$BUILDPLATFORM golang:(\d+\.\d+)-alpine@sha256:([0-9a-f]{64}) AS build$`)
	goDirective = regexp.MustCompile(`(?m)^go (\d+\.\d+)(?:\.\d+)?$`)
)

func TestDockerfileBuilderIsDigestPinnedToTheGoModMinor(t *testing.T) {
	docker, err := os.ReadFile("../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	mod, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	from := builderFrom.FindSubmatch(docker)
	if from == nil {
		t.Fatal("Dockerfile build stage must be golang:<major.minor>-alpine@sha256:<digest> AS build")
	}
	want := goDirective.FindSubmatch(mod)
	if want == nil {
		t.Fatal("go.mod has no go directive")
	}
	if string(from[1]) != string(want[1]) {
		t.Errorf("builder is golang:%s but go.mod needs %s", from[1], want[1])
	}
}

func TestDependabotTracksTheDockerfileDigest(t *testing.T) {
	raw, err := os.ReadFile("../.github/dependabot.yml")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Updates []struct {
			Ecosystem string `yaml:"package-ecosystem"`
			Directory string `yaml:"directory"`
			Schedule  struct {
				Interval string `yaml:"interval"`
			} `yaml:"schedule"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, u := range cfg.Updates {
		if u.Ecosystem == "docker" && u.Directory == "/" {
			if u.Schedule.Interval != "weekly" && u.Schedule.Interval != "daily" {
				t.Errorf("docker updates run %q; want daily or weekly", u.Schedule.Interval)
			}
			return
		}
	}
	t.Error("dependabot.yml has no docker entry for /, so the Dockerfile builder digest is never bumped")
}
