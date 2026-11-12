package app

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/store"
)

type AssignmentRow struct {
	RulesetID string `json:"rulesetId"`
	RuleID    string `json:"ruleId"`
	IsDefault bool   `json:"isDefault"`
	Index     *int   `json:"index,omitempty"`
	Revision  string `json:"revision,omitempty"`
}
type AssignmentRequest struct {
	Operation      string          `json:"operation"`
	Role           string          `json:"role,omitempty"`
	Rows           []AssignmentRow `json:"rows,omitempty"`
	Source         string          `json:"source,omitempty"`
	Target         string          `json:"target,omitempty"`
	Fallback       []string        `json:"fallback,omitempty"`
	SubscriptionID string          `json:"subscriptionId,omitempty"`
}
type AssignmentChange struct {
	Kind        string   `json:"kind"`
	RulesetName string   `json:"rulesetName,omitempty"`
	Name        string   `json:"name"`
	Role        string   `json:"role,omitempty"`
	RuleKey     string   `json:"ruleKey,omitempty"`
	Position    int      `json:"position,omitempty"`
	Disabled    bool     `json:"disabled,omitempty"`
	Indirect    bool     `json:"indirect,omitempty"`
	Before      []string `json:"before"`
	After       []string `json:"after"`
	Detail      string   `json:"detail,omitempty"`
}
type AssignmentPreview struct {
	Token    string             `json:"token"`
	Changes  []AssignmentChange `json:"changes"`
	Warnings []string           `json:"warnings"`
}

type assignmentPlan struct {
	AssignmentPreview
	restore restorePlan
	removed map[string]bool
	req     AssignmentRequest
}

func (p *assignmentPlan) write(file string) {
	if !slices.Contains(p.restore.writes, file) {
		p.restore.writes = append(p.restore.writes, file)
	}
}
func (p *assignmentPlan) change(kind, name, detail string, before, after []string) {
	p.Changes = append(p.Changes, AssignmentChange{Kind: kind, Name: name, Detail: detail, Before: before, After: after})
}

var assignmentDigestKey = []byte(rand.Text())

func (c *Controller) PreviewAssignments(req AssignmentRequest) (AssignmentPreview, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.planAssignmentsLocked(req)
	if err != nil {
		return AssignmentPreview{}, err
	}
	return p.AssignmentPreview, nil
}

func (c *Controller) planAssignmentsLocked(req AssignmentRequest) (*assignmentPlan, error) {
	if c.settingsBroken != nil || c.profilesBroken != nil || c.rulesetsBroken != nil {
		return nil, errors.New("Не удалось прочитать правила или серверы")
	}
	p := &assignmentPlan{req: req, removed: map[string]bool{}, AssignmentPreview: AssignmentPreview{Changes: []AssignmentChange{}, Warnings: []string{}}}
	p.restore.next = c.snapshotLocked()
	next := &p.restore.next
	// Bind confirmation to the original assignments, including changes that
	// happen to have the same visible result (e.g. a different duplicate).
	digest := hmac.New(sha256.New, assignmentDigestKey)
	enc := json.NewEncoder(digest)
	for _, part := range []any{req, next.Settings.Config, next.Rulesets, next.Profiles, next.Groups, next.Proxies, next.Subs, c.rsRev, c.settingsRev.Load()} {
		if err := enc.Encode(part); err != nil {
			return nil, err
		}
	}
	switch req.Operation {
	case "set", "replace":
		if req.Role != "primary" && req.Role != "fallback" && !(req.Operation == "replace" && req.Role == "both") {
			return nil, errors.New("Выберите роль назначения")
		}
		if c.groupsBroken != nil && (req.Target != "" || len(req.Fallback) > 0) {
			return nil, errors.New("Не удалось загрузить группы серверов")
		}
		targets := []string{req.Target}
		if req.Operation == "set" && req.Role == "fallback" {
			targets = req.Fallback
		}
		for _, id := range targets {
			if id != "" && !c.targetExistsLocked(id) {
				return nil, errors.New("Выбранный сервер или группа больше не существует")
			}
		}
	case "transfer", "deleteSubscription":
		if req.Role != "" || len(req.Rows) > 0 {
			return nil, errors.New("Глобальный перенос должен охватывать все назначения")
		}
		if c.subsBroken != nil || c.groupsBroken != nil || c.proxiesBroken != nil {
			return nil, errors.New("Нельзя проверить все подписки, группы и локальные прокси")
		}
		if err := c.planRemovalLocked(p); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("Неизвестное действие с назначениями")
	}
	if err := c.planRuleChangesLocked(p); err != nil {
		return nil, err
	}
	p.restore.rules.rulesets = next.Rulesets
	if err := enc.Encode(p.Changes); err != nil {
		return nil, err
	}

	p.Token = hex.EncodeToString(digest.Sum(nil))
	return p, nil
}

type assignmentRule struct {
	AssignmentChange
	primary  *string
	fallback *[]string
}
type assignmentSelection struct {
	rules        map[string]AssignmentRow
	indexes      map[int]AssignmentRow
	defaultRoute bool
}

func (c *Controller) planRuleChangesLocked(p *assignmentPlan) error {
	req := p.req
	all := req.Operation == "transfer" || req.Operation == "deleteSubscription"
	selected := map[string]*assignmentSelection{}
	for _, r := range req.Rows {
		x := selected[r.RulesetID]
		if x == nil {
			x = &assignmentSelection{rules: map[string]AssignmentRow{}, indexes: map[int]AssignmentRow{}}
			selected[r.RulesetID] = x
		}
		switch {
		case r.IsDefault:
			x.defaultRoute = true
		case r.Index != nil && *r.Index >= 0 && r.Revision != "":
			x.indexes[*r.Index] = r
		case r.Index == nil && r.RuleID != "":
			x.rules[r.RuleID] = r
		default:
			return errors.New("Список правил устарел, откройте его заново")
		}
	}
	next := &p.restore.next
	active := c.activeRulesetIDLocked()
	visit := func(id, label string, cfg *rules.Config, activeProfile bool) error {
		if label == "" {
			label = defaultRulesetName
		}
		x := selected[id]
		if !all && x == nil {
			return nil
		}
		delete(selected, id)
		rev := uint64(0)
		if !activeProfile {
			rev = c.rsRev
		}
		revision := fmt.Sprintf("%d/%d", c.settingsRev.Load(), rev)
		if !all && len(x.rules) > 0 {
			seen := map[string]bool{}
			for _, rule := range cfg.Rules {
				if _, chosen := x.rules[rule.ID]; chosen && seen[rule.ID] {
					return ErrPlanChanged
				}
				seen[rule.ID] = true
			}
		}
		count := len(p.Changes)
		for i := range cfg.Rules {
			r := &cfg.Rules[i]
			if !all {
				_, byID := x.rules[r.ID]
				row, byIndex := x.indexes[i]
				if !byID && !byIndex {
					continue
				}
				if byIndex && (row.Revision != revision || r.ID != row.RuleID) {
					return ErrPlanChanged
				}
				delete(x.indexes, i)
				delete(x.rules, r.ID)
			}
			if r.Action != rules.Tunnel {
				continue
			}
			name := r.Name
			if name == "" {
				name = fmt.Sprintf("Правило %d", i+1)
			}
			ref := assignmentRule{AssignmentChange: AssignmentChange{Kind: "rule", RuleKey: fmt.Sprintf("%s/%d", id, i), Name: name, RulesetName: label, Disabled: r.Enabled != nil && !*r.Enabled}, primary: &r.Profile, fallback: &r.Fallback}
			p.updateRoute(ref)
		}
		if !all && (len(x.rules) > 0 || len(x.indexes) > 0) {
			return ErrPlanChanged
		}
		if (all || x.defaultRoute) && cfg.DefaultAction == rules.Tunnel {
			p.updateRoute(assignmentRule{AssignmentChange: AssignmentChange{Kind: "default", RulesetName: label, Name: "Всё остальное"}, primary: &cfg.DefaultProfile, fallback: &cfg.DefaultFallback})
		}
		if count != len(p.Changes) {
			if err := checkRules(*cfg); err != nil {
				return err
			}
			if activeProfile {
				p.write("settings.json")
			} else {
				p.write("rulesets.json")
			}
		}
		return nil
	}
	if err := visit(active, c.activeRulesetNameLocked(), &next.Settings.Config, true); err != nil {
		return err
	}
	if next.Rulesets != nil {
		for i := range next.Rulesets.List {
			e := &next.Rulesets.List[i]
			if e.ID == active {
				continue
			}
			if (all || selected[e.ID] != nil) && e.Newer() {
				return sentencef("Профиль «%s» создан более новой версией: перенос нельзя проверить", e.Name)
			}
			if err := visit(e.ID, e.Name, &e.Config, false); err != nil {
				return err
			}
		}
	}
	if len(selected) > 0 {
		return ErrPlanChanged
	}
	return nil
}

func distinctTargets(ids []string, primary string) []string {
	seen := map[string]bool{primary: true}
	var out []string
	for _, id := range ids {
		if !seen[id] {
			out = append(out, id)
			seen[id] = true
		}
	}
	return out
}

func (p *assignmentPlan) updateRoute(r assignmentRule) {
	req := p.req
	old := *r.primary
	primary := old
	before := *r.fallback
	fb := slices.Clone(before)
	pos := 0
	switch req.Operation {
	case "set":
		if req.Role == "primary" {
			primary = req.Target
		} else {
			fb = slices.Clone(req.Fallback)
		}
	case "replace", "transfer":
		if req.Role != "fallback" && old == req.Source {
			primary = req.Target
		}
		if req.Role != "primary" {
			for i, id := range fb {
				if id == req.Source {
					fb[i] = req.Target
					if pos == 0 {
						pos = i + 1
					}
				}
			}
		}
	case "deleteSubscription":
		if p.removed[old] {
			primary = ""
		}
		fb = fb[:0]
		for i, id := range before {
			if !p.removed[id] {
				fb = append(fb, id)
			} else if pos == 0 {
				pos = i + 1
			}
		}
	}
	if primary == old && slices.Equal(fb, before) {
		return
	}
	fb = distinctTargets(fb, primary)
	if old != primary {
		change := r.AssignmentChange
		change.Role = "primary"
		change.Before = []string{old}
		change.After = []string{primary}
		p.Changes = append(p.Changes, change)
		*r.primary = primary
	}
	if !slices.Equal(before, fb) {
		change := r.AssignmentChange
		change.Role = "fallback"
		change.Position = pos
		change.Before = before
		change.After = fb
		p.Changes = append(p.Changes, change)
		*r.fallback = fb
	}
	if primary == "" && len(fb) == 0 && (old != "" || len(before) > 0) && len(p.Warnings) == 0 {
		p.Warnings = append(p.Warnings, "Эти правила будут использовать основной сервер с главной. После добавления других серверов назначения можно поменять массово.")
	}
}

func (c *Controller) ApplyAssignments(req AssignmentRequest, token string) error {
	if token == "" {
		return ErrPlanChanged
	}
	c.importMu.Lock()
	defer c.importMu.Unlock()
	unlock, release, err := c.lockRestore(nil)
	if err != nil {
		return err
	}
	p, res, err := c.commitAssignmentsLocked(req, token)
	unlock()
	if err == nil && req.Operation == "deleteSubscription" {
		c.Store.DeleteSnapshots(req.SubscriptionID)
		c.Redactor.SetGroup("sub:" + req.SubscriptionID)
	}
	release()
	if err != nil {
		return err
	}
	if len(p.restore.writes) > 0 {
		c.afterRestore(p.restore.writes, false, res, nil)
	}
	return nil
}

func (c *Controller) commitAssignmentsLocked(req AssignmentRequest, token string) (*assignmentPlan, commitResult, error) {
	var result commitResult
	p, err := c.planAssignmentsLocked(req)
	if err != nil {
		return nil, result, err
	}
	if token != p.Token {
		return nil, result, ErrPlanChanged
	}
	if len(p.restore.writes) == 0 {
		return p, result, nil
	}
	files := slices.Clone(p.restore.writes)
	if slices.Contains(files, "settings.json") && !slices.Contains(files, "rulesets.json") {
		files = append(files, "rulesets.json")
	}
	before := map[string]store.RawFile{}
	for _, f := range files {
		r, err := c.Store.ReadRaw(f)
		if err != nil {
			return nil, result, err
		}
		before[f] = r
	}
	if err = c.Store.BeginAssignments(before); err != nil {
		return nil, result, err
	}
	p.restore.beforeInstall = c.Store.EndAssignments
	result, rollbackErr, err := c.commitRestoreLocked(&p.restore, before)
	if err != nil {
		if rollbackErr == nil {
			rollbackErr = c.Store.EndAssignments()
		}
		if rollbackErr != nil {
			pending := fmt.Errorf("Не удалось завершить восстановление назначений: %w. Перезапустите программу", rollbackErr)
			// Recovery will restore every file in the journal, including files whose
			// rollback succeeded. Prevent later writes from being silently lost.
			for _, file := range files {
				c.markBrokenLocked(file, pending)
			}
			return nil, result, pending
		}
		return nil, result, err
	}
	return p, result, nil
}
