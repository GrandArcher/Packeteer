package probe

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// remoteProber is a fakeProber that serves site providers (#230).
type remoteProber struct{ *fakeProber }

func (remoteProber) Remote() {}

func siteFixture(t *testing.T, probers ...NamedProber) *Engine {
	t.Helper()
	far := Provider{Name: "far", Site: "dc-b"}
	e, err := New([]Provider{provA, far}, probers, src(plugin.Target{Prefix: pfx1}), opts())
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())
	return e
}

func siteResult(t *testing.T, e *Engine, provider string) Result {
	t.Helper()
	for _, r := range e.Results() {
		if r.Provider == provider {
			return r
		}
	}
	t.Fatalf("no result for %s in %+v", provider, e.Results())
	return Result{}
}

func TestSiteProviderIsMeasuredOnlyByARemoteProber(t *testing.T) {
	var mu sync.Mutex
	var localSaw, remoteSaw []plugin.ProbeRequest
	local := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		mu.Lock()
		localSaw = append(localSaw, req)
		mu.Unlock()
		return plugin.ProbeResult{Sent: req.Count, RTTs: ms(10)}, nil
	}}
	remote := remoteProber{&fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		mu.Lock()
		remoteSaw = append(remoteSaw, req)
		mu.Unlock()
		return plugin.ProbeResult{Sent: req.Count, RTTs: ms(40), Site: req.Site, Agent: "agent-1"}, nil
	}}}
	e := siteFixture(t, NamedProber{Name: "local", Prober: local}, NamedProber{Name: "agents", Prober: remote})

	for _, r := range localSaw {
		if r.Provider != "transit-a" || r.Site != "" {
			t.Errorf("the local prober was asked %+v", r)
		}
	}
	if len(remoteSaw) == 0 {
		t.Fatal("the remote prober measured nothing")
	}
	for _, r := range remoteSaw {
		if r.Provider != "far" || r.Site != "dc-b" {
			t.Errorf("the remote prober was asked %+v", r)
		}
	}
	far, near := siteResult(t, e, "far"), siteResult(t, e, "transit-a")
	if !far.OK() || far.Site != "dc-b" || far.Agent != "agent-1" || far.Prober != "agents" {
		t.Errorf("far = %+v", far)
	}
	if near.Site != "" || near.Agent != "" {
		t.Errorf("a local measurement carries site %q agent %q", near.Site, near.Agent)
	}
	for _, st := range e.Providers() {
		if st.Name == "far" && (st.Site != "dc-b" || !st.Up) {
			t.Errorf("far status = %+v", st)
		}
	}
}

func TestSiteProviderWithoutARemoteProberHasNoMeasurement(t *testing.T) {
	local := &fakeProber{fn: ok(10)}
	e := siteFixture(t, NamedProber{Name: "local", Prober: local})
	far := siteResult(t, e, "far")
	if far.OK() || !strings.Contains(far.Err, "no prober can serve") {
		t.Fatalf("far = %+v, want an error", far)
	}
	if !siteResult(t, e, "transit-a").OK() {
		t.Fatal("the local provider must still be measured")
	}
}

func TestSourceUnavailableFromAnAgentFailsOnlyThatProviderClosed(t *testing.T) {
	remote := remoteProber{&fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		return plugin.ProbeResult{}, plugin.ErrSourceUnavailable
	}}}
	e := siteFixture(t, NamedProber{Name: "local", Prober: &fakeProber{fn: ok(10)}}, NamedProber{Name: "agents", Prober: remote})
	for _, st := range e.Providers() {
		switch st.Name {
		case "far":
			if st.Up {
				t.Error("far must be down: no agent can measure it")
			}
		default:
			if !st.Up {
				t.Errorf("%s must stay up", st.Name)
			}
		}
	}
}
