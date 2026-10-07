package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// A device's fixed address (ADR-0035). One per device, so it hangs off the
// device rather than being a collection of its own. ownTenant, like the device
// routes: a tenant's addresses are its own estate.
func addressRoutes(mux *http.ServeMux, h *tenantHandlers) {
	mux.HandleFunc("POST /v1/tenants/{name}/devices/{device}/address", h.ownTenant(h.createAddress))
	mux.HandleFunc("GET /v1/tenants/{name}/devices/{device}/address", h.ownTenant(h.getAddress))
	mux.HandleFunc("DELETE /v1/tenants/{name}/devices/{device}/address", h.ownTenant(h.deleteAddress))
}

type addressBody struct {
	// Address is optional: empty takes the lowest free one. A restore sends the
	// one the tenant's state remembers.
	Address string `json:"address,omitempty"`
}

type addressView struct {
	Tenant     string `json:"tenant"`
	Device     string `json:"device"`
	TrustClass string `json:"trust_class"`
	Address    string `json:"address"`
	// MAC is the device's, as registered: what the address is reserved for.
	MAC       string    `json:"mac"`
	FQDN      string    `json:"fqdn"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func addressViewOf(a tenant.IssuedAddress) addressView {
	return addressView{
		Tenant:     a.Tenant,
		Device:     a.Device,
		TrustClass: a.TrustClass,
		Address:    a.Address,
		MAC:        a.MAC,
		FQDN:       a.FQDN,
		Status:     string(a.Status),
		CreatedAt:  a.CreatedAt,
		UpdatedAt:  a.UpdatedAt,
	}
}

func (h *tenantHandlers) createAddress(w http.ResponseWriter, r *http.Request) {
	var body addressBody
	if !decode(w, r, &body) {
		return
	}
	a, err := h.svc.CreateDeviceAddress(r.Context(), r.PathValue("name"), r.PathValue("device"), body.Address)
	if err != nil {
		var step *tenant.StepError
		if errors.As(err, &step) && a.Address != "" {
			// The row exists and the router or the DNS write did not land. The
			// partial object goes back so the caller records the address it was
			// given, and a retry resumes with that one.
			h.logger.Error("backend step failed", "step", step.Step, "err", step.Err)
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error": step.Error(), "address": addressViewOf(a),
			})
			return
		}
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, addressViewOf(a))
}

func (h *tenantHandlers) getAddress(w http.ResponseWriter, r *http.Request) {
	a, err := h.svc.GetDeviceAddress(r.Context(), r.PathValue("name"), r.PathValue("device"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, addressViewOf(a))
}

func (h *tenantHandlers) deleteAddress(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.DeleteDeviceAddress(r.Context(), r.PathValue("name"), r.PathValue("device")); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
