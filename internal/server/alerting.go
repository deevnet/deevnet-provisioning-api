package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/logauth"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// A tenant's alert rule groups (ADR-0023 §5, CHG-0071). ownTenant, like
// devices: a tenant's rules are its own estate.
//
// A group is put by name and replaced whole, which is how the provider
// declares one: the group is the resource, its rules are blocks within it.
func alertRuleGroupRoutes(mux *http.ServeMux, h *tenantHandlers) {
	mux.HandleFunc("GET /v1/tenants/{name}/alert-rule-groups", h.ownTenant(h.listAlertRuleGroups))
	mux.HandleFunc("PUT /v1/tenants/{name}/alert-rule-groups/{group}", h.ownTenant(h.putAlertRuleGroup))
	mux.HandleFunc("GET /v1/tenants/{name}/alert-rule-groups/{group}", h.ownTenant(h.getAlertRuleGroup))
	mux.HandleFunc("DELETE /v1/tenants/{name}/alert-rule-groups/{group}", h.ownTenant(h.deleteAlertRuleGroup))
}

type alertRuleBody struct {
	Alert       string            `json:"alert"`
	Expr        string            `json:"expr"`
	For         string            `json:"for,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type alertRuleGroupBody struct {
	Type      string          `json:"type"`
	Interval  string          `json:"interval,omitempty"`
	Topic     string          `json:"topic"`
	Partition string          `json:"partition,omitempty"`
	Rules     []alertRuleBody `json:"rules"`
}

type alertRuleGroupView struct {
	Tenant    string          `json:"tenant"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Interval  string          `json:"interval"`
	Topic     string          `json:"topic"`
	NtfyTopic string          `json:"ntfy_topic"`
	Partition string          `json:"partition"`
	Rules     []alertRuleBody `json:"rules"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

func alertRuleGroupViewOf(g tenant.AlertRuleGroup) alertRuleGroupView {
	rules := make([]alertRuleBody, 0, len(g.Group.Rules))
	for _, r := range g.Group.Rules {
		rules = append(rules, alertRuleBody(r))
	}
	return alertRuleGroupView{
		Tenant:    g.Tenant,
		Name:      g.Group.Name,
		Type:      g.Group.Type,
		Interval:  g.Group.Interval,
		Topic:     g.Group.Topic,
		NtfyTopic: g.Tenant + "-" + g.Group.Topic,
		Partition: g.Group.Partition,
		Rules:     rules,
		CreatedAt: g.CreatedAt,
		UpdatedAt: g.UpdatedAt,
	}
}

func (h *tenantHandlers) putAlertRuleGroup(w http.ResponseWriter, r *http.Request) {
	var body alertRuleGroupBody
	// Larger than the other bodies: a group may carry 50 rules.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request body must be a JSON alert rule group"})
		return
	}
	req := logauth.AlertGroup{
		Name: r.PathValue("group"), Type: body.Type, Interval: body.Interval,
		Topic: body.Topic, Partition: body.Partition,
	}
	for _, rule := range body.Rules {
		req.Rules = append(req.Rules, logauth.AlertRule(rule))
	}
	g, err := h.svc.PutAlertRuleGroup(r.Context(), r.PathValue("name"), req)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, alertRuleGroupViewOf(g))
}

func (h *tenantHandlers) listAlertRuleGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := h.svc.ListAlertRuleGroups(r.Context(), r.PathValue("name"))
	if err != nil {
		h.fail(w, err)
		return
	}
	out := make([]alertRuleGroupView, 0, len(groups))
	for _, g := range groups {
		out = append(out, alertRuleGroupViewOf(g))
	}
	writeJSON(w, http.StatusOK, map[string]any{"alert_rule_groups": out})
}

func (h *tenantHandlers) getAlertRuleGroup(w http.ResponseWriter, r *http.Request) {
	g, err := h.svc.GetAlertRuleGroup(r.Context(), r.PathValue("name"), r.PathValue("group"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, alertRuleGroupViewOf(g))
}

func (h *tenantHandlers) deleteAlertRuleGroup(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.DeleteAlertRuleGroup(r.Context(), r.PathValue("name"), r.PathValue("group")); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
