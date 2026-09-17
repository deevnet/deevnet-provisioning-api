package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Workloads and published names (ADR-0015 §12, §13). Both are the operator's
// or the tenant's own.
func workloadRoutes(mux *http.ServeMux, h *tenantHandlers) {
	mux.HandleFunc("POST /v1/tenants/{name}/workloads", h.ownTenant(h.createWorkload))
	mux.HandleFunc("GET /v1/tenants/{name}/workloads", h.ownTenant(h.listWorkloads))
	mux.HandleFunc("GET /v1/tenants/{name}/workloads/{workload}", h.ownTenant(h.getWorkload))
	mux.HandleFunc("DELETE /v1/tenants/{name}/workloads/{workload}", h.ownTenant(h.deleteWorkload))

	mux.HandleFunc("PUT /v1/tenants/{name}/records/{record}", h.ownTenant(h.putRecord))
	mux.HandleFunc("GET /v1/tenants/{name}/records", h.ownTenant(h.listRecords))
	mux.HandleFunc("DELETE /v1/tenants/{name}/records/{record}", h.ownTenant(h.deleteRecord))
}

type workloadBody struct {
	Name     string   `json:"name"`
	Cores    int      `json:"cores,omitempty"`
	MemoryMB int      `json:"memory_mb,omitempty"`
	DiskGB   int      `json:"disk_gb,omitempty"`
	SSHKeys  []string `json:"ssh_keys,omitempty"`
}

type workloadView struct {
	Tenant    string    `json:"tenant"`
	Name      string    `json:"name"`
	FQDN      string    `json:"fqdn"`
	Status    string    `json:"status"`
	Ordinal   int       `json:"ordinal"`
	VMID      int       `json:"vmid"`
	MAC       string    `json:"mac"`
	Address   string    `json:"address"`
	Cores     int       `json:"cores"`
	MemoryMB  int       `json:"memory_mb"`
	DiskGB    int       `json:"disk_gb,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (h *tenantHandlers) workloadView(w tenant.Workload) workloadView {
	return workloadView{
		Tenant:    w.Tenant,
		Name:      w.Name,
		FQDN:      w.Name + "." + h.svc.Site.Zone(w.Tenant),
		Status:    string(w.Status),
		Ordinal:   w.Ordinal,
		VMID:      w.VMID,
		MAC:       w.MAC,
		Address:   w.Address,
		Cores:     w.Cores,
		MemoryMB:  w.MemoryMB,
		DiskGB:    w.DiskGB,
		CreatedAt: w.CreatedAt,
		UpdatedAt: w.UpdatedAt,
	}
}

func (h *tenantHandlers) createWorkload(w http.ResponseWriter, r *http.Request) {
	var body workloadBody
	if !decode(w, r, &body) {
		return
	}
	wl, err := h.svc.CreateWorkload(r.Context(), r.PathValue("name"), tenant.WorkloadRequest(body))
	if err != nil {
		var step *tenant.StepError
		if errors.As(err, &step) && wl.Name != "" {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": step.Error(), "workload": h.workloadView(wl)})
			return
		}
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, h.workloadView(wl))
}

func (h *tenantHandlers) listWorkloads(w http.ResponseWriter, r *http.Request) {
	ws, err := h.svc.ListWorkloads(r.Context(), r.PathValue("name"))
	if err != nil {
		h.fail(w, err)
		return
	}
	out := make([]workloadView, 0, len(ws))
	for _, wl := range ws {
		out = append(out, h.workloadView(wl))
	}
	writeJSON(w, http.StatusOK, map[string]any{"workloads": out})
}

func (h *tenantHandlers) getWorkload(w http.ResponseWriter, r *http.Request) {
	wl, err := h.svc.GetWorkload(r.Context(), r.PathValue("name"), r.PathValue("workload"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.workloadView(wl))
}

func (h *tenantHandlers) deleteWorkload(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.DeleteWorkload(r.Context(), r.PathValue("name"), r.PathValue("workload")); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type recordBody struct {
	Address string `json:"address"`
}

func (h *tenantHandlers) putRecord(w http.ResponseWriter, r *http.Request) {
	var body recordBody
	if !decode(w, r, &body) {
		return
	}
	name, tenantName := r.PathValue("record"), r.PathValue("name")
	if err := h.svc.PutRecord(r.Context(), tenantName, name, body.Address); err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"name":    name,
		"fqdn":    name + "." + h.svc.Site.Zone(tenantName),
		"address": body.Address,
	})
}

func (h *tenantHandlers) listRecords(w http.ResponseWriter, r *http.Request) {
	recs, err := h.svc.ListRecords(r.Context(), r.PathValue("name"))
	if err != nil {
		h.fail(w, err)
		return
	}
	out := make([]map[string]string, 0, len(recs))
	for _, rec := range recs {
		out = append(out, map[string]string{
			"name":    rec.Name,
			"fqdn":    rec.Name + "." + h.svc.Site.Zone(rec.Tenant),
			"address": rec.Address,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": out})
}

func (h *tenantHandlers) deleteRecord(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.DeleteRecord(r.Context(), r.PathValue("name"), r.PathValue("record")); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// decode reads a JSON body, answering 400 itself when it cannot.
func decode(w http.ResponseWriter, r *http.Request, into any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request body is not the expected JSON"})
		return false
	}
	return true
}
