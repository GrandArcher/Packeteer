// Package commit is the "commit" scorer.
//
// Score matches the weighted scorer, so performance decisions stay the same
// when this scorer is selected. Plan, in addition, keeps each provider's
// billable 95th at or under its commit and can balance providers that share
// a group.
//
// The projection starts from the telemetry billable figure. An active commit
// improvement is put back on its native provider first, so the result is the
// set of steers that should exist, not a delta on top of last round. A locked
// prefix is a performance steer: its volume is taken off Native and put on
// Current, because that shift is not in the 95th yet, and it is not a commit
// candidate. Flow volume is the traffic a prefix move takes with it. A move
// that would raise loss is refused unless loss_override is set. Precedence
// (lower is preferred) orders destinations ahead of spare capacity and ahead
// of sharing a group. The highest precedence is used only when every lower
// precedence lacks room. Balance moves are the ones that stay inside the
// group. Plan does not announce.
package commit

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "commit"

const (
	defaultLossWeight   = 100
	defaultRTTWeight    = 1
	defaultJitterWeight = 0.5

	// defaultPrecedence is used when a provider omits precedence. Lower is
	// preferred, so an explicit last-resort provider sets a higher number.
	defaultPrecedence = 100
	defaultSlack      = 0.10
	defaultMaxAge     = 15 * time.Minute

	balanceOff          = "off"
	balanceEqual        = "equal"
	balanceProportional = "proportional"
	mbpsEps             = 0.01
	lossEps             = 1e-6
	maxPlanIterations   = 10000
)

func init() { plugin.Scorers.Register(TypeName, New) }

// Config is the commit scorer's config block.
type Config struct {
	LossWeight   *float64 `yaml:"loss_weight"`
	RTTWeight    *float64 `yaml:"rtt_weight"`
	JitterWeight *float64 `yaml:"jitter_weight"`
	// LossOverride allows a commit move onto a path with higher loss.
	// The default refuses that move.
	LossOverride bool `yaml:"loss_override"`
	// Balance is off, equal, or proportional. off only relieves providers
	// that are over commit. equal shares a group's traffic evenly.
	// proportional shares it in proportion to each member's commit.
	Balance string `yaml:"balance"`
	// BalanceSlack is the fractional imbalance that does not move traffic.
	// Nil uses 0.10. Zero balances any gap larger than the measurement epsilon.
	BalanceSlack *float64 `yaml:"balance_slack"`
	// MaxAge ignores a telemetry row older than this. Zero uses 15m.
	// A row with a zero timestamp is not aged out (tests and a snapshot
	// that has samples but no clock).
	MaxAge time.Duration `yaml:"max_age"`
	// MinMbps ignores prefixes below this volume. Zero moves any prefix
	// with a positive volume.
	MinMbps float64 `yaml:"min_mbps"`
}

// Scorer scores performance and plans commit moves.
type Scorer struct {
	plugin.Base
	loss, rtt, jitter float64
	lossOverride      bool
	balance           string
	slack             float64
	maxAge            time.Duration
	minMbps           float64
}

// New is the plugin factory. It does no I/O.
func New(c plugin.Config, _ plugin.Env) (plugin.Scorer, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	s := &Scorer{
		loss: defaultLossWeight, rtt: defaultRTTWeight, jitter: defaultJitterWeight,
		balance: balanceOff, slack: defaultSlack, maxAge: defaultMaxAge,
	}
	for name, pair := range map[string]struct {
		in  *float64
		out *float64
	}{"loss_weight": {cfg.LossWeight, &s.loss}, "rtt_weight": {cfg.RTTWeight, &s.rtt}, "jitter_weight": {cfg.JitterWeight, &s.jitter}} {
		if pair.in == nil {
			continue
		}
		if *pair.in < 0 {
			return nil, fmt.Errorf("%s %v must not be negative", name, *pair.in)
		}
		*pair.out = *pair.in
	}
	if s.loss == 0 && s.rtt == 0 && s.jitter == 0 {
		return nil, fmt.Errorf("at least one weight must be positive")
	}
	switch cfg.Balance {
	case "", balanceOff:
		s.balance = balanceOff
	case balanceEqual, balanceProportional:
		s.balance = cfg.Balance
	default:
		return nil, fmt.Errorf("balance %q is invalid (want off, equal, or proportional)", cfg.Balance)
	}
	if cfg.BalanceSlack != nil {
		if *cfg.BalanceSlack < 0 || *cfg.BalanceSlack > 1 {
			return nil, fmt.Errorf("balance_slack %v must be between 0 and 1", *cfg.BalanceSlack)
		}
		s.slack = *cfg.BalanceSlack
	}
	if cfg.MaxAge < 0 {
		return nil, fmt.Errorf("max_age %s must not be negative", cfg.MaxAge)
	}
	if cfg.MaxAge > 0 {
		s.maxAge = cfg.MaxAge
	}
	if cfg.MinMbps < 0 {
		return nil, fmt.Errorf("min_mbps %v must not be negative", cfg.MinMbps)
	}
	s.minMbps = cfg.MinMbps
	s.lossOverride = cfg.LossOverride
	return s, nil
}

// Score implements plugin.Scorer. Lower is better.
func (s *Scorer) Score(p plugin.PathStats) float64 {
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	return p.LossPct*s.loss + ms(p.RTTAvg)*s.rtt + ms(p.Jitter)*s.jitter
}

// AllowLoss implements plugin.LossOverride.
func (s *Scorer) AllowLoss() bool { return s.lossOverride }

type live struct {
	name      string
	group     string
	prec      int
	cc        bool
	excluded  bool
	up        bool
	commit    float64
	have      bool
	projected float64
	target    float64
}

type placed struct {
	plugin.PlanPrefix
	base string
}

// Plan implements plugin.Planner.
func (s *Scorer) Plan(in plugin.PlanInput) []plugin.PlanMove {
	provs := map[string]*live{}
	var order []string
	for _, p := range in.Providers {
		if p.Name == "" {
			continue
		}
		if _, dup := provs[p.Name]; dup {
			continue
		}
		lv := &live{
			name: p.Name, group: p.Group, prec: p.Precedence,
			cc: p.CCDisable, excluded: p.Excluded, up: p.Up,
		}
		if lv.prec <= 0 {
			lv.prec = defaultPrecedence
		}
		// Excluded providers are not destinations, but traffic already on
		// them can still be moved off when they are over commit.
		if p.HaveRow && p.Up && s.fresh(p.Usage, in.Now) {
			if mbps, ok := p.Usage.BillableMbps(); ok {
				lv.have = true
				lv.commit = p.Usage.CommitMbps
				lv.projected = mbps
			}
		}
		provs[p.Name] = lv
		order = append(order, p.Name)
	}
	sort.Strings(order)

	var prefs []placed
	for _, px := range in.Prefixes {
		if px.Prefix == (netip.Prefix{}) {
			continue
		}
		if px.Locked {
			// Performance already claimed this volume. Count it on the
			// provider it is moving to, and do not commit-steer it.
			shiftLocked(provs, px)
			continue
		}
		if px.VolumeMbps < s.minMbps || px.VolumeMbps <= mbpsEps {
			continue
		}
		base := px.Current
		if base == "" {
			base = px.Native
		}
		if px.Reversible && px.Native != "" && px.Current != "" && px.Current != px.Native {
			if cur := provs[px.Current]; cur != nil && cur.have {
				cur.projected -= px.VolumeMbps
				if cur.projected < 0 {
					cur.projected = 0
				}
			}
			if nat := provs[px.Native]; nat != nil && nat.have {
				nat.projected += px.VolumeMbps
			}
			base = px.Native
		}
		if base == "" {
			continue
		}
		prefs = append(prefs, placed{PlanPrefix: px, base: base})
	}
	sort.SliceStable(prefs, func(i, j int) bool {
		return lessPrefix(prefs[i].Prefix, prefs[j].Prefix)
	})

	moved := map[netip.Prefix]bool{}
	var moves []plugin.PlanMove
	for pass := 0; pass < 3; pass++ {
		n := s.relieve(provs, prefs, moved, &moves)
		b := 0
		if s.balance != balanceOff {
			b = s.balanceGroups(provs, prefs, moved, &moves)
		}
		if n+b == 0 {
			break
		}
	}
	return moves
}

func (s *Scorer) fresh(u plugin.Usage, now time.Time) bool {
	if _, ok := u.BillableMbps(); !ok {
		return false
	}
	if u.Updated.IsZero() || s.maxAge <= 0 || now.IsZero() {
		return true
	}
	age := now.Sub(u.Updated)
	return age >= 0 && age <= s.maxAge
}

// relieve moves prefixes off providers whose projected usage is over commit.
func (s *Scorer) relieve(provs map[string]*live, prefs []placed, moved map[netip.Prefix]bool, moves *[]plugin.PlanMove) int {
	skip := map[string]bool{}
	n := 0
	for guard := 0; guard < maxPlanIterations; guard++ {
		src, excess := heaviestOver(provs, skip)
		if src == nil {
			return n
		}
		pf, dest := s.pick(provs, prefs, src, excess, false, moved)
		if pf == nil {
			skip[src.name] = true
			continue
		}
		s.apply(src, provs[dest], pf, false, moved, moves)
		n++
	}
	return n
}

// balanceGroups spreads traffic inside a group. Members without a fresh
// usage reading keep the group from balancing, so a silent provider is not
// treated as empty capacity.
func (s *Scorer) balanceGroups(provs map[string]*live, prefs []placed, moved map[netip.Prefix]bool, moves *[]plugin.PlanMove) int {
	groups := map[string][]*live{}
	for _, p := range provs {
		if p.group == "" {
			continue
		}
		groups[p.group] = append(groups[p.group], p)
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	n := 0
	for _, name := range names {
		members := groups[name]
		sort.Slice(members, func(i, j int) bool { return members[i].name < members[j].name })
		active, ok := s.balanceSet(members)
		if !ok {
			continue
		}
		s.assignTargets(active)
		skip := map[string]bool{}
		for guard := 0; guard < maxPlanIterations; guard++ {
			src := heaviestImbalance(active, skip, s.slack)
			if src == nil {
				break
			}
			excess := src.projected - src.target
			if excess < mbpsEps {
				excess = mbpsEps
			}
			pf, dest := s.pick(provs, prefs, src, excess, true, moved)
			if pf == nil {
				skip[src.name] = true
				continue
			}
			s.apply(src, provs[dest], pf, true, moved, moves)
			n++
			s.assignTargets(active)
		}
	}
	return n
}

// balanceSet returns the members that share the load. A member that is
// down, excluded, commit-disabled, or missing usage takes the group out
// of balancing when it is not commit-disabled: the missing reading would
// look like spare capacity.
func (s *Scorer) balanceSet(members []*live) ([]*live, bool) {
	var active []*live
	for _, m := range members {
		if m.cc || m.excluded {
			continue
		}
		if !m.up || !m.have || m.commit <= 0 {
			return nil, false
		}
		active = append(active, m)
	}
	if len(active) < 2 {
		return nil, false
	}
	return active, true
}

func (s *Scorer) assignTargets(active []*live) {
	sum, sumC := 0.0, 0.0
	for _, m := range active {
		sum += m.projected
		sumC += m.commit
	}
	for _, m := range active {
		switch s.balance {
		case balanceEqual:
			m.target = sum / float64(len(active))
		default:
			if sumC <= 0 {
				m.target = sum / float64(len(active))
				continue
			}
			m.target = sum * m.commit / sumC
		}
	}
}

func (s *Scorer) pick(provs map[string]*live, prefs []placed, src *live, excess float64, sameGroup bool, moved map[netip.Prefix]bool) (*placed, string) {
	var ge, lt []*placed
	var geDest, ltDest []string
	for i := range prefs {
		pf := &prefs[i]
		if moved[pf.Prefix] || pf.base != src.name {
			continue
		}
		if _, ok := pathLoss(pf.Paths, src.name); !ok {
			continue
		}
		dest := s.chooseDest(provs, src, pf, sameGroup)
		if dest == "" {
			continue
		}
		if pf.VolumeMbps+mbpsEps >= excess {
			ge = append(ge, pf)
			geDest = append(geDest, dest)
		} else {
			lt = append(lt, pf)
			ltDest = append(ltDest, dest)
		}
	}
	if len(ge) > 0 {
		i := smallest(ge)
		return ge[i], geDest[i]
	}
	if len(lt) > 0 {
		i := largest(lt)
		return lt[i], ltDest[i]
	}
	return nil, ""
}

func smallest(ps []*placed) int {
	best := 0
	for i := 1; i < len(ps); i++ {
		if ps[i].VolumeMbps < ps[best].VolumeMbps-mbpsEps ||
			(within(ps[i].VolumeMbps, ps[best].VolumeMbps) && lessPrefix(ps[i].Prefix, ps[best].Prefix)) {
			best = i
		}
	}
	return best
}

func largest(ps []*placed) int {
	best := 0
	for i := 1; i < len(ps); i++ {
		if ps[i].VolumeMbps > ps[best].VolumeMbps+mbpsEps ||
			(within(ps[i].VolumeMbps, ps[best].VolumeMbps) && lessPrefix(ps[i].Prefix, ps[best].Prefix)) {
			best = i
		}
	}
	return best
}

func within(a, b float64) bool { return a >= b-mbpsEps && a <= b+mbpsEps }

func (s *Scorer) chooseDest(provs map[string]*live, src *live, pf *placed, sameGroup bool) string {
	lr, hasLR := lastResort(provs)
	var all, preferred []*live
	for _, p := range provs {
		if !s.canTake(p, src, pf, sameGroup) {
			continue
		}
		all = append(all, p)
		if hasLR && p.prec >= lr {
			continue
		}
		preferred = append(preferred, p)
	}
	cands := preferred
	if len(cands) == 0 {
		cands = all
	}
	if len(cands) == 0 {
		return ""
	}
	sort.SliceStable(cands, func(i, j int) bool {
		return betterDest(cands[i], cands[j])
	})
	return cands[0].name
}

// betterDest orders commit destinations. Lower precedence wins. Group
// membership does not: balance moves are already limited to the group by
// canTake, and a relieve step must not pick a same-group peer ahead of a
// preferred precedence.
func betterDest(a, b *live) bool {
	if a.prec != b.prec {
		return a.prec < b.prec
	}
	ha := a.commit - a.projected
	hb := b.commit - b.projected
	if !within(ha, hb) {
		return ha > hb
	}
	return a.name < b.name
}

func (s *Scorer) canTake(dst, src *live, pf *placed, sameGroup bool) bool {
	if dst == nil || src == nil || dst.name == src.name {
		return false
	}
	if !dst.up || !dst.have || dst.cc || dst.excluded || dst.commit <= 0 {
		return false
	}
	if sameGroup && (src.group == "" || dst.group != src.group) {
		return false
	}
	if dst.projected+pf.VolumeMbps > dst.commit+mbpsEps {
		return false
	}
	if sameGroup && dst.projected+pf.VolumeMbps >= src.projected-pf.VolumeMbps-mbpsEps {
		// The destination would not end strictly lighter than the source,
		// so the next pass would move the prefix back.
		return false
	}
	if _, ok := pathLoss(pf.Paths, dst.name); !ok {
		return false
	}
	if !s.lossOverride {
		srcLoss, ok := pathLoss(pf.Paths, src.name)
		if !ok {
			return false
		}
		dstLoss, _ := pathLoss(pf.Paths, dst.name)
		if dstLoss > srcLoss+lossEps {
			return false
		}
	}
	return true
}

func (s *Scorer) apply(src, dst *live, pf *placed, balancing bool, moved map[netip.Prefix]bool, moves *[]plugin.PlanMove) {
	if dst == nil || pf == nil {
		return
	}
	// Traffic that should sit on the native provider is not an improvement.
	// Mark it moved so the loop does not pick it again.
	if dst.name == pf.Native {
		moved[pf.Prefix] = true
		return
	}
	vol := pf.VolumeMbps
	before := src.projected
	src.projected -= vol
	if src.projected < 0 {
		src.projected = 0
	}
	dst.projected += vol
	pf.base = dst.name
	moved[pf.Prefix] = true
	reason := fmt.Sprintf("commit: %s %.1f/%.1f Mbps, move %.1f Mbps to %s", src.name, before, src.commit, vol, dst.name)
	if balancing {
		reason = fmt.Sprintf("balance: group %s %s %.1f Mbps to %s", src.group, src.name, vol, dst.name)
	}
	*moves = append(*moves, plugin.PlanMove{
		Prefix: pf.Prefix, Provider: dst.name, Reason: reason, ReliefMbps: vol,
	})
}

// shiftLocked moves a performance steer's volume off Native onto Current.
// The 95th still has that traffic on Native. Leaving it there makes commit
// control move the same traffic a second time.
func shiftLocked(provs map[string]*live, px plugin.PlanPrefix) {
	if px.VolumeMbps <= mbpsEps {
		return
	}
	from, to := px.Native, px.Current
	if from == "" || to == "" || from == to {
		return
	}
	if src := provs[from]; src != nil && src.have {
		src.projected -= px.VolumeMbps
		if src.projected < 0 {
			src.projected = 0
		}
	}
	if dst := provs[to]; dst != nil && dst.have {
		dst.projected += px.VolumeMbps
	}
}

func heaviestOver(provs map[string]*live, skip map[string]bool) (*live, float64) {
	var src *live
	best := 0.0
	for _, p := range provs {
		if skip[p.name] || !p.have || p.cc || p.commit <= 0 {
			continue
		}
		excess := p.projected - p.commit
		if excess <= mbpsEps {
			continue
		}
		if src == nil || excess > best+mbpsEps || (within(excess, best) && p.name < src.name) {
			src = p
			best = excess
		}
	}
	if src == nil {
		return nil, 0
	}
	return src, best
}

func heaviestImbalance(active []*live, skip map[string]bool, slack float64) *live {
	var src *live
	best := 0.0
	for _, p := range active {
		if skip[p.name] {
			continue
		}
		limit := p.target * (1 + slack)
		if p.projected <= limit+mbpsEps {
			continue
		}
		excess := p.projected - p.target
		if src == nil || excess > best+mbpsEps || (within(excess, best) && p.name < src.name) {
			src = p
			best = excess
		}
	}
	return src
}

// lastResort is the highest precedence among providers that can receive
// commit traffic. It is reported only when some other provider is preferred,
// so equal precedences have no last resort.
func lastResort(provs map[string]*live) (int, bool) {
	minP, maxP, n := 0, 0, 0
	for _, p := range provs {
		if !p.up || !p.have || p.cc || p.excluded || p.commit <= 0 {
			continue
		}
		if n == 0 || p.prec < minP {
			minP = p.prec
		}
		if n == 0 || p.prec > maxP {
			maxP = p.prec
		}
		n++
	}
	if n < 2 || maxP <= minP {
		return 0, false
	}
	return maxP, true
}

func pathLoss(paths []plugin.PlanPath, provider string) (float64, bool) {
	for _, p := range paths {
		if p.Provider == provider && p.Usable {
			return p.LossPct, true
		}
	}
	return 0, false
}

func lessPrefix(a, b netip.Prefix) bool {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c < 0
	}
	return a.Bits() < b.Bits()
}
