//go:build windows || darwin

package main

import (
	"log/slog"
	"os"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/stats"
)

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// ctlBackend is ctlserver.API over the GUI and the controller: the calls
// the window makes.
type ctlBackend struct{ g *GUI }

func (b ctlBackend) Version() (string, string)              { return b.g.ctl.Version, b.g.coreVersion() }
func (b ctlBackend) Status() app.Status                     { return b.g.ctl.Status() }
func (b ctlBackend) ConnectOrResume() (bool, error)         { return b.g.ctl.ConnectOrResume() }
func (b ctlBackend) Reconnect() error                       { return b.g.ctl.Reconnect() }
func (b ctlBackend) Disconnect()                            { b.g.ctl.Disconnect() }
func (b ctlBackend) Profiles() []app.ProfileSummary         { return b.g.ctl.Profiles() }
func (b ctlBackend) ResolveTarget(s string) (string, error) { return b.g.ctl.ResolveTarget(s) }
func (b ctlBackend) TargetName(id string) string            { return b.g.ctl.TargetName(id) }
func (b ctlBackend) SetMain(id string) error                { return b.g.ctl.SetMain(id) }
func (b ctlBackend) CheckProfile(id string) (app.CheckResult, error) {
	return b.g.ctl.CheckProfile(id)
}
func (b ctlBackend) Explain(q app.ExplainQuery) app.Explanation { return b.g.ctl.Explain(q, nil) }
func (b ctlBackend) RulesText() string                          { return b.g.ctl.RulesText() }
func (b ctlBackend) RulesJSON() ([]byte, error)                 { return b.g.ctl.RulesJSON() }
func (b ctlBackend) ParseRulesTextAs(content, format string, replace bool) app.RulesTextResult {
	return b.g.ctl.ParseRulesTextAs(content, format, replace)
}
func (b ctlBackend) ApplyRulesTextAs(content, format string, replace bool) (app.SaveResult, app.RulesTextResult, error) {
	return b.g.ctl.ApplyRulesTextAs(content, format, replace, app.EditGuard{})
}
func (b ctlBackend) Subscriptions() []app.SubView { return b.g.ctl.Subscriptions() }
func (b ctlBackend) ResolveSubscription(q string) (string, error) {
	return b.g.ctl.ResolveSubscription(q)
}
func (b ctlBackend) UpdateSubscription(id string) (app.MergeStats, error) {
	return b.g.ctl.UpdateSubscription(id)
}
func (b ctlBackend) Logs(kind string, after uint64) []logx.Entry { return b.g.ctl.Logs(kind, after) }
func (b ctlBackend) LogsTail(kind string, n int) []logx.Entry    { return b.g.ctl.LogsTail(kind, n) }
func (b ctlBackend) Sanitizer() func(string) string              { return b.g.ctl.SanitizeFunc() }
func (b ctlBackend) Mode() string                                { m, _ := b.g.ctl.CLIMode(); return m }
func (b ctlBackend) Log() *slog.Logger                           { return b.g.ctl.Log }
func (b ctlBackend) Groups() app.GroupsInfo                      { return b.g.ctl.Groups() }
func (b ctlBackend) Rulesets() app.RulesetsView                  { return b.g.ctl.Rulesets() }
func (b ctlBackend) ResolveRuleset(q string) (string, error)     { return b.g.ctl.ResolveRuleset(q) }
func (b ctlBackend) SwitchRuleset(id string, src app.Source, o app.SwitchOptions) (app.SwitchResult, error) {
	return b.g.ctl.SwitchRuleset(id, src, o)
}
func (b ctlBackend) NetModes(refresh bool) app.NetModesView { return b.g.ctl.NetModes(refresh) }
func (b ctlBackend) ApplyNetModes(confirmDisconnect string) (app.NetModesView, error) {
	return b.g.ctl.ApplyNetModes(confirmDisconnect)
}
func (b ctlBackend) SetNetModesEnabled(on bool) (app.NetModesView, error) {
	return b.g.ctl.SetNetModesEnabled(on)
}
func (b ctlBackend) Stats(period string) (stats.Report, error) { return b.g.ctl.Stats(period) }
func (b ctlBackend) BrowserOn() bool                           { return b.g.ctl.BrowserOn() }
func (b ctlBackend) BrowserInfo(q app.BrowserQuery) (app.BrowserInfo, error) {
	return b.g.ctl.BrowserInfo(q)
}
func (b ctlBackend) BrowserAdd(e app.BrowserEdit) (app.BrowserResult, error) {
	return b.g.ctl.BrowserAdd(e)
}
func (b ctlBackend) BrowserRemove(e app.BrowserEdit) (app.BrowserResult, error) {
	return b.g.ctl.BrowserRemove(e)
}

// ShowWindow brings the window up, opening it if it is closed.
func (b ctlBackend) ShowWindow() error {
	b.g.showWindow()
	return nil
}
