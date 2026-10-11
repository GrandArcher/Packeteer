package configedit

import (
	"reflect"
	"strings"
)

// ---- normalize and compare ----

func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.TrimSpace(s))
	}
	return out
}

func trimEach(ps ...*string) {
	for _, p := range ps {
		*p = strings.TrimSpace(*p)
	}
}

func (f *Form) normalizeSections() {
	f.normalizeProtection()
	for i := range f.Flows {
		fl := &f.Flows[i]
		fl.Listen = trimAll(fl.Listen)
		fl.Exclude = trimAll(fl.Exclude)
		trimEach(&fl.Key, &fl.Name, &fl.Window, &fl.TopN, &fl.MaxTargets, &fl.TailInterval, &fl.MinBytes, &fl.MinPct, &fl.AggregateV4, &fl.AggregateV6)
	}
	for i := range f.Policies {
		p := &f.Policies[i]
		trimEach(&p.Key, &p.Name, &p.GeoIPDB)
		if p.Rules == nil {
			p.Rules = []FormRule{}
		}
		for j := range p.Rules {
			r := &p.Rules[j]
			trimEach(&r.Key, &r.Name, &r.Action, &r.Traffic, &r.MaxLossPct, &r.MaxRTT)
			r.Providers = trimAll(r.Providers)
			r.Prefixes = trimAll(r.Prefixes)
			r.ASNs = trimAll(r.ASNs)
			r.Countries = trimAll(r.Countries)
		}
	}
	for i := range f.VIPs {
		v := &f.VIPs[i]
		trimEach(&v.Key, &v.Name, &v.Interval, &v.MaxTargets)
		v.ASNs = trimAll(v.ASNs)
		if v.Prefixes == nil {
			v.Prefixes = []FormTarget{}
		}
		for j := range v.Prefixes {
			t := &v.Prefixes[j]
			trimEach(&t.Key, &t.Prefix, &t.Host)
		}
	}
	for i := range f.Outages {
		o := &f.Outages[i]
		trimEach(&o.Key, &o.Name, &o.MinPrefixes, &o.Window, &o.LossPct, &o.RTTMs, &o.Interval, &o.MaxTargets)
		o.IgnoreASNs = trimAll(o.IgnoreASNs)
	}
}

// fillSections gives a nil section the file's current value, so a request
// that omits it changes nothing. Every list becomes non-nil.
func (f *Form) fillSections(cur Form) {
	f.fillProtection(cur)
	if f.Flows == nil {
		f.Flows = cur.Flows
	}
	if f.Policies == nil {
		f.Policies = cur.Policies
	}
	if f.VIPs == nil {
		f.VIPs = cur.VIPs
	}
	if f.Outages == nil {
		f.Outages = cur.Outages
	}
	for i := range f.Flows {
		fl := &f.Flows[i]
		if fl.Listen == nil {
			fl.Listen = []string{}
		}
		if fl.Exclude == nil {
			fl.Exclude = []string{}
		}
	}
	for i := range f.VIPs {
		v := &f.VIPs[i]
		if v.ASNs == nil {
			v.ASNs = []string{}
		}
	}
	for i := range f.Outages {
		if f.Outages[i].IgnoreASNs == nil {
			f.Outages[i].IgnoreASNs = []string{}
		}
	}
	for i := range f.Policies {
		for j := range f.Policies[i].Rules {
			r := &f.Policies[i].Rules[j]
			for _, l := range []*[]string{&r.Providers, &r.Prefixes, &r.ASNs, &r.Countries} {
				if *l == nil {
					*l = []string{}
				}
			}
		}
	}
}

// withoutUnchangedSections drops the sections the operator did not edit,
// so a file the form does not fully model still lets the other fields be
// applied. Save runs the full checks either way.
func (f Form) withoutUnchangedSections(cur Form) Form {
	if reflect.DeepEqual(f.Flows, cur.Flows) {
		f.Flows = nil
	}
	if reflect.DeepEqual(f.Policies, cur.Policies) {
		f.Policies = nil
	}
	if reflect.DeepEqual(f.VIPs, cur.VIPs) {
		f.VIPs = nil
	}
	if reflect.DeepEqual(f.Outages, cur.Outages) {
		f.Outages = nil
	}
	if reflect.DeepEqual(f.Inbound, cur.Inbound) {
		f.Inbound = nil
	}
	if reflect.DeepEqual(f.Anomaly, cur.Anomaly) {
		f.Anomaly = nil
	}
	return f
}

func sectionsEqual(f, g Form) bool {
	return reflect.DeepEqual(f.Flows, g.Flows) && reflect.DeepEqual(f.Policies, g.Policies) &&
		reflect.DeepEqual(f.VIPs, g.VIPs) && reflect.DeepEqual(f.Outages, g.Outages) && protectionEqual(f, g)
}
