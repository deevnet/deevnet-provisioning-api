package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/logauth"
)

// Tenant alerting (ADR-0023 §5, CHG-0071).
//
// A tenant declares rule groups; each group's rules run in the tenant's own
// vmalert on the observability store, reading with the tenant's log read
// token, and its alerts reach the tenant's ntfy topic <tenant>-<topic>. The
// tenant's phone subscribes with an ntfy login issued here, like the
// dashboard login.
//
// The log store's writer carries all of it: the API sends the tenant's whole
// alerting state - the login and every group - in one request, and the writer
// renders vmalert's rules, Alertmanager's routes and ntfy's users from every
// tenant's. A group is sent before it is stored, so a group the writer or
// vmalert refuses is never recorded as the tenant's.

const StepAlerting = "alerting"

// ErrAlertingNotOffered is a rule-group request at a site without alerting.
var ErrAlertingNotOffered = &InvalidError{Reason: "this site offers no alerting"}

// Alerting is the log store's writer, as alerting sees it.
type Alerting interface {
	PutAlerts(ctx context.Context, t AlertTenant) error
}

// AlertTenant is one tenant's whole alerting state.
type AlertTenant struct {
	Name           string
	Index          int
	NotifyPassword string
	Groups         []logauth.AlertGroup
}

// AlertRuleGroup is one of a tenant's rule groups, as the registry holds it.
type AlertRuleGroup struct {
	Tenant    string
	Group     logauth.AlertGroup
	CreatedAt time.Time
	UpdatedAt time.Time
}

// AlertRuleGroupRequest is a tenant declaring a group. Interval and Partition
// may be empty for their defaults.
type AlertRuleGroupRequest = logauth.AlertGroup

func (s *Service) alertingTenant(ctx context.Context, tenantName string) (Record, error) {
	if s.Alerting == nil || s.Site.NotifyEndpoint == "" {
		return Record{}, ErrAlertingNotOffered
	}
	rec, err := s.Store.Get(ctx, tenantName)
	if err != nil {
		return Record{}, err
	}
	if rec.Status != StatusReady {
		return Record{}, invalid("tenant %q is %s", tenantName, rec.Status)
	}
	if rec.Secrets.NotifyPassword == "" || rec.Secrets.LogRead == "" {
		return Record{}, invalid("tenant %q has no alerting login yet; reconcile it first", tenantName)
	}
	return rec, nil
}

// PutAlertRuleGroup creates or replaces one of a tenant's rule groups.
func (s *Service) PutAlertRuleGroup(ctx context.Context, tenantName string, req AlertRuleGroupRequest) (AlertRuleGroup, error) {
	rec, err := s.alertingTenant(ctx, tenantName)
	if err != nil {
		return AlertRuleGroup{}, err
	}
	g := req
	if g.Interval == "" {
		g.Interval = logauth.DefaultAlertPeriod
	}
	if g.Partition == "" {
		g.Partition = logauth.PartitionWorkloads
	}
	if err := g.Validate(); err != nil {
		return AlertRuleGroup{}, invalid("%s", err.Error())
	}

	existing, err := s.Store.ListAlertRuleGroups(ctx, tenantName)
	if err != nil {
		return AlertRuleGroup{}, err
	}
	groups := make([]logauth.AlertGroup, 0, len(existing)+1)
	for _, e := range existing {
		if e.Group.Name != g.Name {
			groups = append(groups, e.Group)
		}
	}
	groups = append(groups, g)
	if err := s.pushAlerts(ctx, rec, groups); err != nil {
		return AlertRuleGroup{}, err
	}
	out, err := s.Store.PutAlertRuleGroup(ctx, AlertRuleGroup{Tenant: tenantName, Group: g})
	if err != nil {
		return AlertRuleGroup{}, err
	}
	rules := make([]string, 0, len(g.Rules))
	for _, r := range g.Rules {
		rules = append(rules, r.Alert)
	}
	s.audit(ctx, "alert-rule-group-put", tenantName, map[string]any{
		"group": g.Name, "type": g.Type, "topic": g.Topic, "partition": g.Partition, "rules": rules,
	})
	return out, nil
}

// GetAlertRuleGroup returns one of a tenant's rule groups.
func (s *Service) GetAlertRuleGroup(ctx context.Context, tenantName, name string) (AlertRuleGroup, error) {
	return s.Store.GetAlertRuleGroup(ctx, tenantName, name)
}

// ListAlertRuleGroups returns a tenant's rule groups.
func (s *Service) ListAlertRuleGroups(ctx context.Context, tenantName string) ([]AlertRuleGroup, error) {
	return s.Store.ListAlertRuleGroups(ctx, tenantName)
}

// DeleteAlertRuleGroup removes a rule group: from the writer first, so its
// rules stop running, then from the registry. The tenant's last group gone,
// its vmalert stops.
func (s *Service) DeleteAlertRuleGroup(ctx context.Context, tenantName, name string) error {
	if _, err := s.Store.GetAlertRuleGroup(ctx, tenantName, name); err != nil {
		return err
	}
	rec, err := s.alertingTenant(ctx, tenantName)
	if err != nil {
		return err
	}
	existing, err := s.Store.ListAlertRuleGroups(ctx, tenantName)
	if err != nil {
		return err
	}
	var groups []logauth.AlertGroup
	for _, e := range existing {
		if e.Group.Name != name {
			groups = append(groups, e.Group)
		}
	}
	if err := s.pushAlerts(ctx, rec, groups); err != nil {
		return err
	}
	s.audit(ctx, "alert-rule-group-delete", tenantName, map[string]any{"group": name})
	return s.Store.DeleteAlertRuleGroup(ctx, tenantName, name)
}

// pushAlerts sends a tenant's whole alerting state with these groups. The
// limits across groups are checked here, before the writer sees them, and a
// refusal of the tenant's own rules - by the writer or by vmalert - comes back
// to the tenant as a 400.
func (s *Service) pushAlerts(ctx context.Context, rec Record, groups []logauth.AlertGroup) error {
	state := logauth.Alerts{NotifyPassword: rec.Secrets.NotifyPassword, Groups: groups}
	if state.Groups == nil {
		state.Groups = []logauth.AlertGroup{}
	}
	if err := state.Validate(); err != nil {
		return invalid("%s", err.Error())
	}
	// The request has to fit the writer's input bound, with room for the
	// envelope around it.
	if body, err := json.Marshal(state); err != nil {
		return err
	} else if len(body) > logauth.MaxRequestBytes-(4<<10) {
		return invalid("the tenant's rule groups together are larger than %d bytes", logauth.MaxRequestBytes-(4<<10))
	}
	err := s.Alerting.PutAlerts(ctx, AlertTenant{
		Name: rec.Name, Index: rec.Index, NotifyPassword: rec.Secrets.NotifyPassword, Groups: state.Groups,
	})
	var bad *InvalidError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &bad):
		return err
	default:
		return &StepError{Step: StepAlerting, Err: err}
	}
}

// ensureAlerting mints the tenant's ntfy login if the registry holds none,
// and writes its whole alerting state: on a create, the login alone; on a
// reconcile, every group it has, into a store that may have been rebuilt.
func (s *Service) ensureAlerting(ctx context.Context, rec Record) error {
	if s.Alerting == nil || s.Site.NotifyEndpoint == "" {
		return nil
	}
	if rec.Secrets.NotifyPassword == "" {
		pw, err := randomHex(24)
		if err != nil {
			return err
		}
		secrets := rec.Secrets
		secrets.NotifyPassword = pw
		if err := s.Store.SetSecrets(ctx, rec.Name, secrets); err != nil {
			return err
		}
		rec.Secrets = secrets
	}
	existing, err := s.Store.ListAlertRuleGroups(ctx, rec.Name)
	if err != nil {
		return err
	}
	groups := make([]logauth.AlertGroup, 0, len(existing))
	for _, e := range existing {
		groups = append(groups, e.Group)
	}
	return s.Alerting.PutAlerts(ctx, AlertTenant{
		Name: rec.Name, Index: rec.Index, NotifyPassword: rec.Secrets.NotifyPassword, Groups: groups,
	})
}
