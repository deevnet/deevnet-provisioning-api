package server

import (
	"net/http"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Server certificates for a tenant's own services (ADR-0037, CHG-0047). A
// tenant's own, or the operator's on its behalf - ownTenant, as for every
// other thing a tenant holds: a certificate is a statement about names in one
// tenant's zone, and only that tenant may ask for it.
//
// PUT, by name, because asking is an ensure: the same request for the same
// label returns the same certificate until it is close to expiry.
func certificateRoutes(mux *http.ServeMux, h *tenantHandlers) {
	mux.HandleFunc("PUT /v1/tenants/{name}/certificates/{certificate}", h.ownTenant(h.putCertificate))
	mux.HandleFunc("GET /v1/tenants/{name}/certificates", h.ownTenant(h.listCertificates))
	mux.HandleFunc("GET /v1/tenants/{name}/certificates/{certificate}", h.ownTenant(h.getCertificate))
	mux.HandleFunc("DELETE /v1/tenants/{name}/certificates/{certificate}", h.ownTenant(h.deleteCertificate))
}

type certificateBody struct {
	// CSR is a PEM PKCS#10 signing request. It is read for its public key,
	// and for its signature, which shows the sender holds the private key.
	// Its subject, its names and its extensions are not used.
	CSR string `json:"csr"`
	// Names are further labels, beside the certificate's own. Labels, not
	// names: the API builds every name, so a tenant cannot spell one outside
	// its own.
	Names []string `json:"names,omitempty"`
	// Sites are the sites to name the certificate at beside its site-less
	// names, among those the API issues for. Empty means this site alone.
	Sites []string `json:"sites,omitempty"`
}

type certificateView struct {
	Tenant string `json:"tenant"`
	Name   string `json:"name"`
	// FQDN is the certificate's own name and its common name.
	FQDN string `json:"fqdn"`
	// Names is every DNS name it is valid for, fully qualified, its own first.
	Names []string `json:"names"`
	// Certificate is the leaf, PEM. CAChain is what a server presents after
	// it: the Tenant Service CA and the Site CA, and never the root, which a
	// client holds. Nothing here is secret.
	Certificate string `json:"certificate"`
	CAChain     string `json:"ca_chain"`
	Serial      string `json:"serial"`
	// KeyFingerprint is the SHA-256 of the public key certified, in hex.
	KeyFingerprint string    `json:"key_fingerprint"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	// RenewAfter is when asking again issues a new certificate: sixty days
	// before it expires. Nothing renews it for a tenant that does not ask.
	RenewAfter time.Time `json:"renew_after"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func certificateViewOf(c tenant.Certificate) certificateView {
	v := certificateView{
		Tenant:         c.Tenant,
		Name:           c.Name,
		Names:          emptyIfNil(c.Names),
		Certificate:    c.PEM,
		CAChain:        c.Chain,
		Serial:         c.Serial,
		KeyFingerprint: c.KeyFingerprint,
		NotBefore:      c.NotBefore,
		NotAfter:       c.NotAfter,
		RenewAfter:     c.RenewAfter(),
		CreatedAt:      c.CreatedAt,
		UpdatedAt:      c.UpdatedAt,
	}
	if len(c.Names) > 0 {
		v.FQDN = c.Names[0]
	}
	return v
}

func (h *tenantHandlers) putCertificate(w http.ResponseWriter, r *http.Request) {
	var body certificateBody
	if !decode(w, r, &body) {
		return
	}
	c, issued, err := h.svc.PutCertificate(r.Context(), r.PathValue("name"), r.PathValue("certificate"),
		tenant.CertificateRequest(body))
	if err != nil {
		h.fail(w, err)
		return
	}
	// 201 when this call issued one, 200 when it returned the one it had. A
	// caller that wants to know whether its certificate changed can tell
	// without comparing serials.
	status := http.StatusOK
	if issued {
		status = http.StatusCreated
	}
	writeJSON(w, status, certificateViewOf(c))
}

func (h *tenantHandlers) listCertificates(w http.ResponseWriter, r *http.Request) {
	certs, err := h.svc.ListCertificates(r.Context(), r.PathValue("name"))
	if err != nil {
		h.fail(w, err)
		return
	}
	out := make([]certificateView, 0, len(certs))
	for _, c := range certs {
		out = append(out, certificateViewOf(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificates": out})
}

func (h *tenantHandlers) getCertificate(w http.ResponseWriter, r *http.Request) {
	c, err := h.svc.GetCertificate(r.Context(), r.PathValue("name"), r.PathValue("certificate"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, certificateViewOf(c))
}

func (h *tenantHandlers) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.DeleteCertificate(r.Context(), r.PathValue("name"), r.PathValue("certificate")); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
