package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/zapret"
)

// Self-healing of the DPI bypass («Следить и подбирать самому»): while
// the bypass runs, HyRoute opens the services' check addresses through it
// now and then, as a browser would (zapret.Live). When one stops opening
// twice in a row, and still opens without a bypass or is blocked in a way
// a bypass can beat, it picks again by itself (the library, the spares,
// the generator). So does it on a network with no pick yet. A network
// that is down or blocks by address is left alone, and picks are spaced
// out so a lasting block does not have it pick all day.

// Test hooks.
var (
	zapretHealFirst = time.Minute      // after the bypass starts
	zapretHealEvery = 10 * time.Minute // between checks
	zapretHealAgain = time.Minute      // a failed check is repeated before acting
	zapretHealGap   = 30 * time.Minute // between automatic picks on a network
	zapretHealIdle  = 2 * time.Hour    // after one that left a service without a method
	// zapretHealWake: after the computer slept, the network takes a while
	// to come back; checks wait this long.
	zapretHealWake = 2 * time.Minute
)

// zapretHealLocked runs zapretHeal while the bypass is on with it.
func (c *Controller) zapretHealLocked(cfg zapret.Settings) {
	want := c.zapretErr == nil && cfg.Enabled && cfg.Heals() && len(cfg.Targets) > 0 && c.ZapretPrepare != nil && c.ZapretLists != ""
	if want == (c.healStop != nil) {
		return
	}
	if !want {
		c.healStop()
		c.healStop = nil
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.healStop = cancel
	c.healWG.Add(1)
	go func() {
		defer c.healWG.Done()
		c.zapretHeal(ctx)
	}()
}

// stopHeal ends self-healing and waits for it (tests).
func (c *Controller) stopHeal() {
	c.zapretMu.Lock()
	if c.healStop != nil {
		c.healStop()
		c.healStop = nil
	}
	c.zapretMu.Unlock()
	c.healWG.Wait()
}

func (c *Controller) zapretHeal(ctx context.Context) {
	t := time.NewTimer(zapretHealFirst)
	defer t.Stop()
	// The wall clock: the timer's clock may not count sleep (Windows), the
	// wall clock does, so a gap far past the interval is a sleep.
	due := time.Now().Round(0).Add(zapretHealFirst)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if late := time.Now().Round(0).Sub(due); late > zapretHealWake {
			c.Log.Info("zapret: self-healing: the computer slept; checking later", "late", late.Round(time.Second))
			due = time.Now().Round(0).Add(zapretHealWake)
			t.Reset(zapretHealWake)
			continue
		}
		c.zapretHealOnce(ctx)
		due = time.Now().Round(0).Add(zapretHealEvery)
		t.Reset(zapretHealEvery)
	}
}

func (c *Controller) healState() (string, int64) {
	c.pickMu.Lock()
	defer c.pickMu.Unlock()
	if c.healAt.IsZero() {
		return c.healNote, 0
	}
	return c.healNote, c.healAt.UnixMilli()
}

func (c *Controller) setHeal(note string) {
	c.pickMu.Lock()
	c.healNote, c.healAt = note, time.Now()
	c.pickMu.Unlock()
	c.changed()
}

// healTargets: the services self-healing looks after: automatic ones
// (not a method the user fixed, not the VPN) it can check by name.
func healTargets(cfg zapret.Settings) []zapret.Target {
	var out []zapret.Target
	for _, t := range cfg.Targets {
		if cfg.On(t) && cfg.Methods[t] == zapret.Auto && len(zapret.Checks(t, cfg.Sites)) > 0 {
			out = append(out, t)
		}
	}
	return out
}

func targetNames(ts []zapret.Target) string {
	var n []string
	for _, t := range ts {
		n = append(n, zapret.TargetName(t))
	}
	return strings.Join(n, ", ")
}

// zapretHealOnce is one round: check, and pick when it must.
func (c *Controller) zapretHealOnce(ctx context.Context) {
	c.pickMu.Lock()
	picking := c.pickCancel != nil
	c.pickMu.Unlock()
	if picking {
		return // the user's pick: it decides
	}
	key, _ := c.zapretNetKey()
	started := time.Now()
	c.zapretMu.Lock()
	cfg := cloneZapretSettings(c.zapretCfg) // read below without zapretMu
	running := c.zapretArgs != nil && c.zapretRunner().Status().State == zapret.Running
	c.zapretMu.Unlock()
	targets := healTargets(cfg)
	if len(targets) == 0 || ctx.Err() != nil {
		return
	}
	if _, ok := cfg.Picked[key]; !ok {
		c.healPick(ctx, key, started, "на этой сети ещё не подбирали методы", targets)
		return
	}
	// Through the bypass as it runs: with a plan winws2 must be up (it
	// restarts by itself when it fell); without one nothing touches them.
	var check []zapret.Target
	for _, t := range targets {
		if _, ok := cfg.PlanFor(t, key); ok && !running {
			return
		}
		check = append(check, t)
	}
	// Own sites found dead here by the pick are not checked.
	urls := func(t zapret.Target) []string { return zapret.ChecksSkip(t, cfg.Sites, cfg.Picked[key].SkippedSites) }
	failing, _ := c.healCheck(ctx, zapret.Live, check, urls)
	if ctx.Err() != nil {
		return
	}
	if len(failing) == 0 {
		c.setHeal("Проверено: " + targetNames(check) + " открывается")
		return
	}
	// Once more a little later: a single miss is not a broken method.
	select {
	case <-ctx.Done():
		return
	case <-time.After(zapretHealAgain):
	}
	failing, how := c.healCheck(ctx, zapret.Live, failing, urls)
	if len(failing) == 0 || ctx.Err() != nil {
		return
	}
	// Without a bypass: is it blocked so a bypass can help, or is the
	// network down, the site blocked by address?
	var need []zapret.Target
	var notes []string
	for _, t := range failing {
		r := zapretCheckFunc(ctx, 0, urls(t))
		_, planned := cfg.PlanFor(t, key)
		switch {
		case r.OK && !planned:
			// Opens without a bypass and runs without one: a miss.
		case r.OK || r.Bypassable():
			need = append(need, t)
		default:
			d := r.Diagnosis()
			notes = append(notes, fmt.Sprintf("%s не открывается и без обхода (%s): обход тут не поможет", zapret.TargetName(t), d.Kind.Explain()))
		}
	}
	if ctx.Err() != nil {
		return
	}
	if len(need) > 0 {
		// What failed through the bypass, for the note (not the log: own
		// sites are the user's).
		var what []string
		for _, t := range need {
			if r, ok := how[t]; ok && len(r.Failed) > 0 {
				what = append(what, r.Diagnosis().String())
			}
		}
		why := targetNames(need) + " перестал открываться через обход"
		if len(what) > 0 {
			why += " (" + strings.Join(what, "; ") + ")"
		}
		c.Log.Info("zapret: self-healing: stopped opening", "targets", targetNames(need))
		c.healPick(ctx, key, started, why, need)
		return
	}
	if len(notes) > 0 {
		c.setHeal(strings.Join(notes, "; "))
		c.Log.Info("zapret: self-healing: not a bypass's case", "targets", len(notes))
	}
}

// healCheck returns the targets that did not open from slot.
func (c *Controller) healCheck(ctx context.Context, slot int, ts []zapret.Target, urls func(zapret.Target) []string) ([]zapret.Target, map[zapret.Target]zapret.Result) {
	type res struct {
		t zapret.Target
		r zapret.Result
	}
	ch := make(chan res, len(ts))
	for _, t := range ts {
		go func() { ch <- res{t, zapretCheckFunc(ctx, slot, urls(t))} }()
	}
	var bad []zapret.Target
	how := map[zapret.Target]zapret.Result{}
	for range ts {
		if r := <-ch; !r.r.OK {
			bad = append(bad, r.t)
			how[r.t] = r.r
		}
	}
	// In the settings' order.
	var out []zapret.Target
	for _, t := range ts {
		for _, b := range bad {
			if b == t {
				out = append(out, t)
			}
		}
	}
	return out, how
}

// healPick picks again for the network unless one did not long ago, or
// one ran since the round began at started (the user's «Подобрать»: it
// decides, and its result is what the page shows).
func (c *Controller) healPick(ctx context.Context, key string, started time.Time, why string, ts []zapret.Target) {
	c.pickMu.Lock()
	last := c.autoPicks[key]
	c.pickMu.Unlock()
	gap := zapretHealGap
	if !last.found {
		gap = zapretHealIdle
	}
	if !last.at.IsZero() && time.Since(last.at) < gap {
		c.setHeal(fmt.Sprintf("%s: подбирал недавно, попробую снова после %s", why, last.at.Add(gap).Format("15:04")))
		return
	}
	c.Log.Info("zapret: self-healing: picking again", "targets", targetNames(ts))
	c.zapretMu.Lock()
	if ctx.Err() != nil {
		c.zapretMu.Unlock()
		return
	}
	if pk, ok := c.zapretCfg.Picked[key]; ok && pk.At.After(started) {
		c.zapretMu.Unlock()
		c.Log.Info("zapret: self-healing: a pick ran meanwhile, none again")
		return
	}
	v, err := c.zapretPickLocked(capFirst(why))
	c.zapretMu.Unlock()
	// A pick that could not run (winws2 did not start) is no verdict on
	// the network: the usual gap, not the long one.
	found := err != nil || v.Pick != nil
	var lost []zapret.Target
	if err == nil && v.Pick != nil {
		for _, t := range ts {
			if v.Pick.Results[t] == "" {
				lost = append(lost, t)
			}
		}
		found = len(lost) == 0
	}
	c.pickMu.Lock()
	if c.autoPicks == nil {
		c.autoPicks = map[string]autoPick{}
	}
	c.autoPicks[key] = autoPick{at: time.Now(), found: found}
	c.pickMu.Unlock()
	switch {
	case err != nil:
		c.setHeal(fmt.Sprintf("%s: подобрать заново не вышло — %v. Попробую снова через %d мин", why, err, int(zapretHealGap.Minutes())))
	case len(lost) > 0:
		c.setHeal(fmt.Sprintf("%s: ни один метод не открыл %s. Попробую снова через %d ч; если не поможет — пустите через VPN", why, targetNames(lost), int(zapretHealIdle.Hours())))
	default:
		c.setHeal(why + ": подобрал заново, обход работает")
	}
}
