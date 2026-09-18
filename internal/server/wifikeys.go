package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Tenant Wi-Fi keys (ADR-0012 §3). A tenant's own, or the operator's on its
// behalf - ownTenant, not knownCaller, because knownCaller admits any
// registered tenant without scoping by name, and these are credentials.
func wifiKeyRoutes(mux *http.ServeMux, h *tenantHandlers) {
	mux.HandleFunc("POST /v1/tenants/{name}/wifi-keys", h.ownTenant(h.createWiFiKey))
	mux.HandleFunc("GET /v1/tenants/{name}/wifi-keys", h.ownTenant(h.listWiFiKeys))
	mux.HandleFunc("GET /v1/tenants/{name}/wifi-keys/{key}", h.ownTenant(h.getWiFiKey))
	mux.HandleFunc("DELETE /v1/tenants/{name}/wifi-keys/{key}", h.ownTenant(h.deleteWiFiKey))
}

type wifiKeyBody struct {
	Name       string `json:"name"`
	TrustClass string `json:"trust_class"`
	// PSK is the restore path only: the tenant putting back the key it already
	// holds, after the API lost its copy (ADR-0012 §5). Left empty, the API
	// mints one, and re-applying keeps the key that is already there.
	PSK string `json:"psk,omitempty"`
}

type wifiKeyView struct {
	Tenant     string `json:"tenant"`
	Name       string `json:"name"`
	TrustClass string `json:"trust_class"`
	// SSID and VLAN are reported, never chosen. A tenant should not hardcode an
	// SSID: the same trust class is DVNTM-IOT at one site and DVNT-IOT at another.
	SSID   string `json:"ssid"`
	VLAN   int    `json:"vlan"`
	Status string `json:"status"`
	// PSK appears on the create response only, never on a read. The holder
	// already has it in its own state; what a read needs to say is whether the
	// key still exists and whether the API's copy is intact.
	PSK string `json:"psk,omitempty"`
	// SecretsStored is false when the API holds a PSK it can no longer open, so
	// the tenant knows to supply it again (ADR-0016 §6).
	SecretsStored bool      `json:"secrets_stored"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// wifiKeyView renders a key. issued is true only on the create response.
func wifiKeyViewOf(k tenant.IssuedWiFiKey, issued bool) wifiKeyView {
	v := wifiKeyView{
		Tenant:        k.Tenant,
		Name:          k.Name,
		TrustClass:    k.TrustClass,
		SSID:          k.SSID,
		VLAN:          k.VLAN,
		Status:        string(k.Status),
		SecretsStored: !k.Unreadable,
		CreatedAt:     k.CreatedAt,
		UpdatedAt:     k.UpdatedAt,
	}
	if issued {
		v.PSK = k.PSK
	}
	return v
}

func (h *tenantHandlers) createWiFiKey(w http.ResponseWriter, r *http.Request) {
	var body wifiKeyBody
	if !decode(w, r, &body) {
		return
	}
	k, err := h.svc.CreateWiFiKey(r.Context(), r.PathValue("name"), tenant.WiFiKeyRequest(body))
	if err != nil {
		var step *tenant.StepError
		if errors.As(err, &step) && k.Name != "" {
			// The row exists and the controller write did not land. The partial
			// object goes back with the PSK, so a retry supplies the same one
			// rather than minting a second key for the same devices.
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error": step.Error(), "wifi_key": wifiKeyViewOf(k, true),
			})
			return
		}
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, wifiKeyViewOf(k, true))
}

func (h *tenantHandlers) listWiFiKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.svc.ListWiFiKeys(r.Context(), r.PathValue("name"))
	if err != nil {
		h.fail(w, err)
		return
	}
	out := make([]wifiKeyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, wifiKeyViewOf(k, false))
	}
	writeJSON(w, http.StatusOK, map[string]any{"wifi_keys": out})
}

func (h *tenantHandlers) getWiFiKey(w http.ResponseWriter, r *http.Request) {
	k, err := h.svc.GetWiFiKey(r.Context(), r.PathValue("name"), r.PathValue("key"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wifiKeyViewOf(k, false))
}

func (h *tenantHandlers) deleteWiFiKey(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.DeleteWiFiKey(r.Context(), r.PathValue("name"), r.PathValue("key")); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
