package server

import (
	"net/http"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// The tenant device registry (ADR-0012 §3). A tenant's own devices, or the
// operator's on its behalf - ownTenant, not knownCaller, because knownCaller
// admits any registered tenant without scoping by name, and a tenant's device
// list is its own estate.
func deviceRoutes(mux *http.ServeMux, h *tenantHandlers) {
	mux.HandleFunc("POST /v1/tenants/{name}/devices", h.ownTenant(h.createDevice))
	mux.HandleFunc("GET /v1/tenants/{name}/devices", h.ownTenant(h.listDevices))
	mux.HandleFunc("GET /v1/tenants/{name}/devices/{device}", h.ownTenant(h.getDevice))
	mux.HandleFunc("DELETE /v1/tenants/{name}/devices/{device}", h.ownTenant(h.deleteDevice))
}

type deviceBody struct {
	Name       string `json:"name"`
	TrustClass string `json:"trust_class"`
	// MAC is optional and is recorded, not enforced. Nothing the substrate does
	// turns on it (ADR-0020 §2).
	MAC string `json:"mac,omitempty"`
}

type deviceView struct {
	Tenant     string    `json:"tenant"`
	Name       string    `json:"name"`
	TrustClass string    `json:"trust_class"`
	MAC        string    `json:"mac,omitempty"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func deviceViewOf(d tenant.Device) deviceView {
	return deviceView{
		Tenant:     d.Tenant,
		Name:       d.Name,
		TrustClass: d.TrustClass,
		MAC:        d.MAC,
		Status:     string(d.Status),
		CreatedAt:  d.CreatedAt,
		UpdatedAt:  d.UpdatedAt,
	}
}

func (h *tenantHandlers) createDevice(w http.ResponseWriter, r *http.Request) {
	var body deviceBody
	if !decode(w, r, &body) {
		return
	}
	// No StepError case, unlike createWiFiKey: registering a device calls no
	// backend, so there is no half-applied state to hand back.
	d, err := h.svc.CreateDevice(r.Context(), r.PathValue("name"), tenant.DeviceRequest(body))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, deviceViewOf(d))
}

func (h *tenantHandlers) listDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := h.svc.ListDevices(r.Context(), r.PathValue("name"))
	if err != nil {
		h.fail(w, err)
		return
	}
	out := make([]deviceView, 0, len(devices))
	for _, d := range devices {
		out = append(out, deviceViewOf(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

func (h *tenantHandlers) getDevice(w http.ResponseWriter, r *http.Request) {
	d, err := h.svc.GetDevice(r.Context(), r.PathValue("name"), r.PathValue("device"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, deviceViewOf(d))
}

func (h *tenantHandlers) deleteDevice(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.DeleteDevice(r.Context(), r.PathValue("name"), r.PathValue("device")); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
