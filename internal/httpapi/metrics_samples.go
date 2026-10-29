package httpapi

import (
	"math"
	"strconv"
	"strings"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// parseMetrics reads back the text writeSeries renders: one `# TYPE` line
// per metric, then `name{k="v",...} value` lines. Non-finite values are
// skipped because the push sinks cannot store them.
func parseMetrics(text []byte) []plugin.MetricSample {
	var out []plugin.MetricSample
	counters := map[string]bool{}
	for _, line := range strings.Split(string(text), "\n") {
		if rest, ok := strings.CutPrefix(line, "# TYPE "); ok {
			if name, typ, ok := strings.Cut(rest, " "); ok {
				counters[name] = typ == "counter"
			}
			continue
		}
		if line == "" || line[0] == '#' {
			continue
		}
		name, labels, rest, ok := splitSample(line)
		if !ok {
			continue
		}
		v, err := strconv.ParseFloat(rest, 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		out = append(out, plugin.MetricSample{Name: name, Counter: counters[name], Labels: labels, Value: v})
	}
	return out
}

// splitSample cuts a sample line into the metric name, its labels, and the
// value text.
func splitSample(line string) (name string, labels map[string]string, value string, ok bool) {
	i := strings.IndexAny(line, "{ ")
	if i < 0 {
		return "", nil, "", false
	}
	name = line[:i]
	if line[i] == ' ' {
		return name, nil, line[i+1:], true
	}
	labels = map[string]string{}
	rest := line[i+1:]
	for !strings.HasPrefix(rest, "}") {
		k, after, found := strings.Cut(rest, `="`)
		if !found {
			return "", nil, "", false
		}
		var v strings.Builder
		j := 0
		for ; j < len(after) && after[j] != '"'; j++ {
			c := after[j]
			if c == '\\' && j+1 < len(after) {
				j++
				if c = after[j]; c == 'n' {
					c = '\n'
				}
			}
			v.WriteByte(c)
		}
		if j >= len(after) {
			return "", nil, "", false
		}
		labels[k] = v.String()
		rest = strings.TrimPrefix(after[j+1:], ",")
	}
	value, found := strings.CutPrefix(rest[1:], " ")
	return name, labels, value, found
}
