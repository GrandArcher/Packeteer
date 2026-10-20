package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/internal/federation"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// settingsReceiver applies a settings push from a federation peer (#137).
// It goes through the same editor and online apply as PUT /api/config, so
// a pushed section passes every check a start does and takes effect with
// no restart and no withdraw. It writes only the sections in
// federation.PushableSections, and a push that would also change any
// other key, or need a restart, is refused. It never touches mode, the
// allowlist, or the announcer.
type settingsReceiver struct {
	editor httpapi.ConfigEditor
	apply  httpapi.OnlineApplier
	audit  *auth.Auditor

	// mu keeps one push at a time, so the file read, the check, and the
	// write see the same file.
	mu sync.Mutex
}

// handle is the plugin.SettingsHandler.
func (r *settingsReceiver) handle(ctx context.Context, from string, req plugin.SettingsPush) plugin.SettingsResult {
	res := r.run(ctx, req)
	names := sectionNames(req.Sections)
	rec := plugin.AuditRecord{Actor: from, Method: auth.MethodFederation, Role: plugin.RoleAdmin,
		Action: "federation.settings", Target: strings.Join(names, ","), Result: auth.ResultOK}
	rec.Detail = res.Status
	if len(res.Applied) > 0 {
		rec.Detail += " applied " + strings.Join(res.Applied, ",")
	}
	if len(res.Errors) > 0 {
		rec.Detail += ": " + strings.Join(res.Errors, "; ")
	}
	switch res.Status {
	case plugin.SettingsRefused:
		rec.Result = auth.ResultDenied
	case plugin.SettingsFailed:
		rec.Result = auth.ResultFailed
	}
	r.audit.Record(ctx, rec)
	return res
}

func sectionNames(m map[string]string) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

func refusedWith(format string, args ...any) plugin.SettingsResult {
	return plugin.SettingsResult{Status: plugin.SettingsRefused, Errors: []string{fmt.Sprintf(format, args...)}}
}

func (r *settingsReceiver) run(ctx context.Context, req plugin.SettingsPush) plugin.SettingsResult {
	names := sectionNames(req.Sections)
	if len(names) == 0 {
		return refusedWith("the push carries no sections")
	}
	want := make(map[string]string, len(names))
	for _, n := range names {
		if !slices.Contains(federation.PushableSections, n) {
			return refusedWith("section %q cannot be pushed (allowed: %s)", n, strings.Join(federation.PushableSections, ", "))
		}
		text, err := configedit.CanonicalSection(req.Sections[n])
		if err != nil {
			return refusedWith("section %s: %v", n, err)
		}
		want[n] = text
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	file, err := r.editor.Read()
	if err != nil {
		return plugin.SettingsResult{Status: plugin.SettingsFailed, Errors: []string{"cannot read the config file: " + err.Error()}}
	}
	have, err := configedit.ReadSections([]byte(file.YAML), names)
	if err != nil {
		return plugin.SettingsResult{Status: plugin.SettingsFailed, Errors: []string{err.Error()}}
	}
	if maps.Equal(have, want) {
		return plugin.SettingsResult{Status: plugin.SettingsUnchanged}
	}
	merged, err := configedit.ReplaceSections([]byte(file.YAML), want)
	if err != nil {
		return refusedWith("%v", err)
	}
	chk := r.editor.Check(merged)
	switch {
	case !chk.Valid:
		return plugin.SettingsResult{Status: plugin.SettingsRefused, Errors: chk.Errors}
	case chk.EnablesInject:
		return refusedWith("a push never turns inject on")
	}
	for _, k := range chk.Changed {
		if !slices.Contains(names, k) {
			return refusedWith("the config file also differs from the running config in %s; apply or revert that first", k)
		}
	}
	if !chk.ReloadOnline && len(chk.Changed) > 0 {
		return refusedWith("the change cannot be applied online")
	}
	if _, _, err := r.editor.Save(merged, file.SHA256, false); err != nil {
		if errors.Is(err, configedit.ErrConflict) {
			return refusedWith("the config file changed during the push; send it again")
		}
		return plugin.SettingsResult{Status: plugin.SettingsFailed, Errors: []string{"cannot write the config file: " + err.Error()}}
	}
	applied, refused, fatal := r.apply(ctx)
	switch {
	case fatal != nil:
		return plugin.SettingsResult{Status: plugin.SettingsFailed, Applied: applied, Errors: []string{fatal.Error()}}
	case refused != nil:
		res := refusedWith("the online apply was refused: %v", refused)
		// The file must match what runs, or the next restart would start
		// from a section the instance refused.
		if _, _, err := r.editor.Save([]byte(file.YAML), configedit.Hash(merged), false); err != nil {
			res.Errors = append(res.Errors, "the previous config file could not be restored: "+err.Error())
		}
		return res
	}
	return plugin.SettingsResult{Status: plugin.SettingsApplied, Applied: applied}
}

// push sends sections of this instance's config file to peers (all
// configured peers when peers is empty) and reports each one's answer.
// Peers are asked in parallel; a dead peer costs one push timeout, not one
// per peer.
func (f *fedState) push(ctx context.Context, sections, peers []string) (federation.PushReport, error) {
	if f == nil || f.editor == nil {
		return federation.PushReport{}, errors.New("settings push needs federation and http.config_editor")
	}
	if len(sections) == 0 {
		return federation.PushReport{}, errors.New("name at least one section")
	}
	for _, s := range sections {
		if !slices.Contains(federation.PushableSections, s) {
			return federation.PushReport{}, fmt.Errorf("section %q cannot be pushed (allowed: %s)", s, strings.Join(federation.PushableSections, ", "))
		}
	}
	configured := f.peerNames()
	if len(peers) == 0 {
		peers = configured
	}
	for _, p := range peers {
		if !slices.Contains(configured, p) {
			return federation.PushReport{}, fmt.Errorf("%q is not a configured federation peer", p)
		}
	}
	file, err := f.editor.Read()
	if err != nil {
		return federation.PushReport{}, fmt.Errorf("cannot read the config file: %w", err)
	}
	body, err := configedit.ReadSections([]byte(file.YAML), sections)
	if err != nil {
		return federation.PushReport{}, err
	}
	out := make([]federation.PeerPush, len(peers))
	var wg sync.WaitGroup
	for i, p := range peers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := f.fed.Push(ctx, p, plugin.SettingsPush{Sections: body})
			if err != nil {
				out[i] = federation.PeerPush{Peer: p, Status: federation.Unreachable, Errors: []string{err.Error()}}
				return
			}
			out[i] = federation.PeerPush{Peer: p, Status: res.Status, Applied: res.Applied, Errors: res.Errors}
		}()
	}
	wg.Wait()
	return federation.NewPushReport(sections, out), nil
}

func (f *fedState) peerNames() []string {
	var names []string
	for _, p := range f.fed.Peers(time.Now()) {
		names = append(names, p.Name)
	}
	return names
}

// acceptSettings installs the handler for pushes from peers. The
// transport only lets through the certificates in accept_settings_from.
func (f *fedState) acceptSettings(apply httpapi.OnlineApplier, audit *auth.Auditor) {
	if f == nil || f.editor == nil {
		return
	}
	r := &settingsReceiver{editor: f.editor, apply: apply, audit: audit}
	f.fed.SetSettingsHandler(r.handle)
}
