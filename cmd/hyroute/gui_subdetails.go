//go:build windows || darwin

package main

import "github.com/lardan099/hyroute/internal/app"

func (g *GUI) SubscriptionDetails(id string) (app.SubReport, error) {
	return g.ctl.SubscriptionDetails(id)
}
