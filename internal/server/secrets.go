package server

import (
	"net/http"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Tenant runtime secrets (ADR-0021, CHG-0067). A tenant's own, or the
// operator's on its behalf: ownTenant, as for broker accounts.
//
// A secret's path may hold "/", so it is the rest of the URL. It may also be
// sent as one segment with each "/" escaped as %2F; the mux matches on the
// escaped path and PathValue unescapes it, so both reach the service the
// same.
func secretRoutes(mux *http.ServeMux, h *tenantHandlers) {
	mux.HandleFunc("PUT /v1/tenants/{name}/secrets/{path...}", h.ownTenant(h.putSecret))
	mux.HandleFunc("GET /v1/tenants/{name}/secrets/{path...}", h.ownTenant(h.getSecret))
	mux.HandleFunc("DELETE /v1/tenants/{name}/secrets/{path...}", h.ownTenant(h.deleteSecret))
	mux.HandleFunc("PUT /v1/tenants/{name}/secret-readers/{reader}", h.ownTenant(h.putSecretReader))
	mux.HandleFunc("GET /v1/tenants/{name}/secret-readers/{reader}", h.ownTenant(h.getSecretReader))
	mux.HandleFunc("DELETE /v1/tenants/{name}/secret-readers/{reader}", h.ownTenant(h.deleteSecretReader))
}

type secretBody struct {
	// Data is the value: written to OpenBao and nowhere else, never returned.
	Data map[string]string `json:"data"`
	// Version is the tenant's, 1 or more. A new value comes with a new one.
	Version int `json:"version"`
}

// secretView never carries a value. The API's own OpenBao policy cannot read
// one.
type secretView struct {
	Path    string `json:"path"`
	Version int    `json:"version"`
	// Present is always true when the API answers 200: a secret OpenBao no
	// longer holds is a 404, so the provider writes it again.
	Present bool `json:"present"`
}

type secretReaderBody struct {
	Workload string   `json:"workload"`
	Paths    []string `json:"paths"`
}

type secretReaderView struct {
	Name     string   `json:"name"`
	Workload string   `json:"workload"`
	Paths    []string `json:"paths"`
	RoleID   string   `json:"role_id"`
	// SecretID is on the PUT response only. The API does not keep it.
	SecretID  string `json:"secret_id,omitempty"`
	Namespace string `json:"namespace"`
	Addr      string `json:"addr"`
}

func secretViewOf(s tenant.RuntimeSecret) secretView {
	return secretView{Path: s.Path, Version: s.Version, Present: true}
}

func secretReaderViewOf(r tenant.IssuedSecretReader) secretReaderView {
	return secretReaderView{
		Name: r.Name, Workload: r.Workload, Paths: emptyIfNil(r.Paths),
		RoleID: r.RoleID, SecretID: r.SecretID, Namespace: r.Namespace, Addr: r.Addr,
	}
}

func (h *tenantHandlers) putSecret(w http.ResponseWriter, r *http.Request) {
	var body secretBody
	if !decode(w, r, &body) {
		return
	}
	s, err := h.svc.PutRuntimeSecret(r.Context(), r.PathValue("name"), r.PathValue("path"), body.Data, body.Version)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, secretViewOf(s))
}

func (h *tenantHandlers) getSecret(w http.ResponseWriter, r *http.Request) {
	s, err := h.svc.GetRuntimeSecret(r.Context(), r.PathValue("name"), r.PathValue("path"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, secretViewOf(s))
}

func (h *tenantHandlers) deleteSecret(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.DeleteRuntimeSecret(r.Context(), r.PathValue("name"), r.PathValue("path")); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *tenantHandlers) putSecretReader(w http.ResponseWriter, r *http.Request) {
	var body secretReaderBody
	if !decode(w, r, &body) {
		return
	}
	rd, err := h.svc.PutSecretReader(r.Context(), r.PathValue("name"), r.PathValue("reader"), body.Workload, body.Paths)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, secretReaderViewOf(rd))
}

func (h *tenantHandlers) getSecretReader(w http.ResponseWriter, r *http.Request) {
	rd, err := h.svc.GetSecretReader(r.Context(), r.PathValue("name"), r.PathValue("reader"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, secretReaderViewOf(rd))
}

func (h *tenantHandlers) deleteSecretReader(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.DeleteSecretReader(r.Context(), r.PathValue("name"), r.PathValue("reader")); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
