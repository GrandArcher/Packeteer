package policy

import (
	"math"
	"net/netip"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// weighWants sets the improvement weight (#34) of every new static, VIP,
// and performance move when the scorer's weights are on. Commit and cost
// moves keep their relief and savings order. Weights only order moves
// that already passed every check; the cap loop admits them.
func weighWants(wants []pending, scorer plugin.Scorer, volume map[netip.Prefix]float64) {
	wg, ok := scorer.(plugin.ImprovementWeigher)
	if !ok {
		return
	}
	if on, _ := wg.ImprovementWeights(); !on {
		return
	}
	for i := range wants {
		w := &wants[i]
		if w.rank >= rankPlanned {
			continue
		}
		w.weight = wg.ImprovementWeight(plugin.WeightInput{
			Prefix: w.imp.Prefix, Provider: w.imp.Provider, Gain: w.gain, VolumeMbps: volume[w.imp.Prefix],
		})
		if math.IsNaN(w.weight) {
			w.weight = 0
		}
		w.weighed = true
		w.d.Weight = w.weight
	}
}
