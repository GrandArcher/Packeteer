package mikrotik

import (
	"fmt"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/plugins/rosrest"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func init() {
	p, err := Profile(Options{}, nil)
	if err != nil {
		panic(err)
	}
	config.RegisterOffloadProfile(p, checkRouter)
}

// OptionsOf is the profile options of one offload_aware router.
func OptionsOf(r config.OffloadRouter) Options {
	return Options{Model: Model(r.Model), VolumeSource: r.VolumeSource}
}

// RESTConfig is the RouterOS REST login of one offload_aware router.
func RESTConfig(r config.OffloadRouter) rosrest.Config {
	return rosrest.Config{URL: r.URL, UsernameEnv: r.UsernameEnv, PasswordEnv: r.PasswordEnv, CAFile: r.CAFile}
}

// checkRouter refuses a router the profile cannot read: the profile has no
// measurements without the RouterOS reader and its login.
func checkRouter(r config.OffloadRouter) error {
	if r.Reader != config.OffloadReaderRouterOS {
		return fmt.Errorf("profile %s needs reader: %s", ID, config.OffloadReaderRouterOS)
	}
	if err := OptionsOf(r).validate(); err != nil {
		return err
	}
	if _, err := RESTConfig(r).Login(plugin.Env{CheckOnly: true}); err != nil {
		return fmt.Errorf("reader %s: %w", config.OffloadReaderRouterOS, err)
	}
	return nil
}
