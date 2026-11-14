package replay

import (
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
)

// NewSide builds one side of a replay: the decision config of cfg and a
// scorer of its own. Nothing is started and no announcer is built.
func NewSide(name string, cfg *config.Config, opts pluginhost.Options) (Side, error) {
	pc, err := policy.FromConfig(cfg)
	if err != nil {
		return Side{}, err
	}
	sc, err := pluginhost.BuildScorer(cfg, opts)
	if err != nil {
		return Side{}, err
	}
	return Side{Name: name, Cfg: pc, Scorer: sc}, nil
}
