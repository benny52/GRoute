//go:build windows || darwin

package main

import "github.com/lardan099/hyroute/internal/app"

func (g *GUI) PreviewAssignments(req app.AssignmentRequest) (app.AssignmentPreview, error) {
	return g.ctl.PreviewAssignments(req)
}
func (g *GUI) ApplyAssignments(req app.AssignmentRequest, token string) error {
	return g.ctl.ApplyAssignments(req, token)
}
func (g *GUI) ServerAssignments(id string) ([]app.AssignmentChange, error) {
	return g.ctl.ServerAssignments(id)
}
