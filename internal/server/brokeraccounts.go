package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Tenant MQTT broker accounts (ADR-0012 §3, §10; CHG-0016). A tenant's own, or
// the operator's on its behalf - ownTenant, not knownCaller, for the same
// reason as Wi-Fi keys: knownCaller admits any registered tenant without
// scoping by name, and these are credentials.
func brokerAccountRoutes(mux *http.ServeMux, h *tenantHandlers) {
	mux.HandleFunc("POST /v1/tenants/{name}/broker-accounts", h.ownTenant(h.createBrokerAccount))
	mux.HandleFunc("GET /v1/tenants/{name}/broker-accounts", h.ownTenant(h.listBrokerAccounts))
	mux.HandleFunc("GET /v1/tenants/{name}/broker-accounts/{account}", h.ownTenant(h.getBrokerAccount))
	mux.HandleFunc("DELETE /v1/tenants/{name}/broker-accounts/{account}", h.ownTenant(h.deleteBrokerAccount))
}

type brokerAccountBody struct {
	Name string `json:"name"`
	// Device is optional. Empty means a workload account; a named device must
	// belong to this tenant and be in trust class iot (ADR-0012 §3).
	Device string `json:"device,omitempty"`
	// Publish and Subscribe are RELATIVE to the tenant's prefix. The API writes
	// the "<tenant>/" itself (ADR-0012 §10), so a tenant declares
	// "lightstand/+/scene" and never its own name. Sending an absolute pattern
	// is rejected rather than silently accepted, so a tenant that misreads this
	// finds out at apply time instead of when a device fails to publish.
	Publish   []string `json:"publish,omitempty"`
	Subscribe []string `json:"subscribe,omitempty"`
	// Password is the restore path only: the tenant putting back the password
	// it already holds, after the API lost its copy (ADR-0012 §5). A tenant
	// never chooses a new account's password.
	Password string `json:"password,omitempty"`
}

type brokerAccountView struct {
	Tenant string `json:"tenant"`
	Name   string `json:"name"`
	Device string `json:"device,omitempty"`
	// Username is what the broker knows this account as. Derived by the API and
	// reported so a tenant can configure a device without having to know the
	// derivation, or be able to change it.
	Username string `json:"username"`
	// Publish and Subscribe come back ABSOLUTE - prefixed - which is
	// deliberately not what went in. What the tenant sent is what it asked for;
	// what comes back is what the broker will enforce, and seeing the prefix is
	// how a tenant can tell §10 was applied.
	Publish   []string `json:"publish"`
	Subscribe []string `json:"subscribe"`
	Status    string   `json:"status"`
	// Password appears on the create response only, and only when this call
	// minted or was given one. A read never carries it and neither does a
	// re-apply that reused the stored hash: the API holds the hash, not the
	// plaintext (ADR-0012 §4), so there is nothing to return and saying so is
	// better than inventing one.
	Password  string    `json:"password,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// brokerAccountViewOf renders an account. issued is true only on create.
func brokerAccountViewOf(a tenant.IssuedBrokerAccount, issued bool) brokerAccountView {
	v := brokerAccountView{
		Tenant:    a.Tenant,
		Name:      a.Name,
		Device:    a.Device,
		Username:  a.Username,
		Publish:   emptyIfNil(a.Publish),
		Subscribe: emptyIfNil(a.Subscribe),
		Status:    string(a.Status),
		CreatedAt: a.CreatedAt,
		UpdatedAt: a.UpdatedAt,
	}
	if issued {
		v.Password = a.Password
	}
	return v
}

// emptyIfNil keeps an account with no patterns rendering as [] rather than
// null, so a tenant reading "subscribe": [] sees an account that may publish
// and not subscribe, instead of a field it has to guess about.
func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (h *tenantHandlers) createBrokerAccount(w http.ResponseWriter, r *http.Request) {
	var body brokerAccountBody
	if !decode(w, r, &body) {
		return
	}
	a, err := h.svc.CreateBrokerAccount(r.Context(), r.PathValue("name"), tenant.BrokerAccountRequest(body))
	if err != nil {
		var step *tenant.StepError
		if errors.As(err, &step) && a.Name != "" {
			// The row exists and the writer did not land. The partial object
			// goes back WITH the password, so a retry supplies the same one
			// rather than minting a second for devices already flashed with
			// the first.
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error": step.Error(), "broker_account": brokerAccountViewOf(a, true),
			})
			return
		}
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, brokerAccountViewOf(a, true))
}

func (h *tenantHandlers) listBrokerAccounts(w http.ResponseWriter, r *http.Request) {
	accounts, err := h.svc.ListBrokerAccounts(r.Context(), r.PathValue("name"))
	if err != nil {
		h.fail(w, err)
		return
	}
	out := make([]brokerAccountView, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, brokerAccountViewOf(a, false))
	}
	writeJSON(w, http.StatusOK, map[string]any{"broker_accounts": out})
}

func (h *tenantHandlers) getBrokerAccount(w http.ResponseWriter, r *http.Request) {
	a, err := h.svc.GetBrokerAccount(r.Context(), r.PathValue("name"), r.PathValue("account"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, brokerAccountViewOf(a, false))
}

func (h *tenantHandlers) deleteBrokerAccount(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.DeleteBrokerAccount(r.Context(), r.PathValue("name"), r.PathValue("account")); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
