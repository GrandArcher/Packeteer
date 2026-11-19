package main

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
)

const standIn = "registry-stub"

// #657: the lab config builds with the real plugins, stays in observe, and
// every registry it names is the stand-in, with no credential in the file.
func TestLabConfigOnlyNamesTheStandIn(t *testing.T) {
	path := filepath.Join("..", "packeteer-registry.yaml")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "observe" || !cfg.RegistryOn() || !cfg.Registry.PushEnabled {
		t.Fatalf("mode %q registry %v push %v", cfg.Mode, cfg.RegistryOn(), cfg.Registry.PushEnabled)
	}
	// #673: the second scan that offers the delete comes from a short
	// interval, which validation allows for the TEST database only.
	if cfg.Registry.Interval != 3*time.Minute || cfg.Registry.IRR.Source != "TEST" {
		t.Fatalf("interval %s source %s", cfg.Registry.Interval, cfg.Registry.IRR.Source)
	}
	set, err := pluginhost.Build(cfg, pluginhost.Options{Getenv: getenv, CheckOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.IRRSources) != 1 || len(set.RegistryCheckers) != 2 {
		t.Fatalf("irr sources %d, registry sources %d", len(set.IRRSources), len(set.RegistryCheckers))
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var hosts []string
	var walk func(k string, v any)
	walk = func(k string, v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, x := range v {
				walk(k, x)
			}
		case []any:
			for _, x := range v {
				walk(k, x)
			}
		case string:
			// A whois address has a port; a BGP neighbor address does not.
			if k == "base_url" || k == "url" || k == "address" && strings.Contains(v, ":") {
				host := v
				if u, err := url.Parse(v); err == nil && u.Host != "" {
					host = u.Host
				}
				hosts = append(hosts, strings.Split(host, ":")[0])
			}
		}
	}
	walk("", doc)
	if len(hosts) != 5 {
		t.Fatalf("registry addresses in the lab config: %v", hosts)
	}
	for _, h := range hosts {
		if h != standIn {
			t.Errorf("the lab config names %q, not the stand-in", h)
		}
	}
	for _, secret := range []string{labPass, labKey} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the lab config holds a credential")
		}
	}
}

// The lab network has no route out, no service publishes a port, and every
// service is on that one network.
func TestLabComposeIsInternal(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "docker-compose-registry.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]struct {
			Ports    []any `yaml:"ports"`
			Networks map[string]any
		} `yaml:"services"`
		Networks map[string]struct {
			Internal bool `yaml:"internal"`
		} `yaml:"networks"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Networks) != 1 || !doc.Networks["lab"].Internal {
		t.Fatalf("networks %+v", doc.Networks)
	}
	if len(doc.Services) != 4 {
		t.Fatalf("services %d", len(doc.Services))
	}
	for name, s := range doc.Services {
		if len(s.Ports) != 0 || len(s.Networks) != 1 {
			t.Errorf("%s: ports %v networks %v", name, s.Ports, s.Networks)
		}
	}
}
