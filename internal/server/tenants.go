package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/auth"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// The tenant routes (ADR-0015). Every one sits behind the operator token.
func tenantRoutes(mux *http.ServeMux, svc *tenant.Service, logger *slog.Logger) {
	h := &tenantHandlers{svc: svc, logger: logger}
	mux.HandleFunc("POST /v1/admissions", operatorOnly(h.admit))
	mux.HandleFunc("POST /v1/tenants", h.create)
	mux.HandleFunc("GET /v1/tenants", operatorOnly(h.list))
	mux.HandleFunc("GET /v1/tenants/{name}", h.ownTenant(h.get))
	mux.HandleFunc("DELETE /v1/tenants/{name}", h.ownTenant(h.delete))
	mux.HandleFunc("POST /v1/tenants/{name}/reconcile", operatorOnly(h.reconcile))
	mux.HandleFunc("GET /v1/fabric/egress", egressReader(h.egress))
	workloadRoutes(mux, h)
}

// ownTenant admits the operator, and a registered tenant for its own name. A
// tenant asking for another name is told it does not exist.
func (h *tenantHandlers) ownTenant(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := principalFrom(r.Context())
		switch {
		case p.operator:
			next(w, r)
		case p.tenant != "":
			// Another tenant's name is 404 rather than 403, so a token cannot be
			// used to discover which tenants exist.
			//
			// So is the tenant's own name when it is unregistered: the token
			// verifies by its MAC without the registry (ADR-0015 §5), and after
			// a registry loss the tenant it names genuinely is not there. The
			// provider reads that 404 and restores, which is the whole point of
			// a token that outlives the database - a 401 here would leave a
			// tenant unable to put itself back.
			if p.tenant != r.PathValue("name") || !p.registered {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant not found"})
				return
			}
			next(w, r)
		default:
			auth.Deny(w)
		}
	}
}

type admitBody struct {
	Name string `json:"name"`
}

func (h *tenantHandlers) admit(w http.ResponseWriter, r *http.Request) {
	var body admitBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request body must be {\"name\": ...}"})
		return
	}
	adm, err := h.svc.Admit(r.Context(), body.Name)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"name":             adm.Name,
		"enrollment_token": adm.EnrollmentToken,
		"expires_at":       adm.ExpiresAt.UTC(),
	})
}

type tenantHandlers struct {
	svc    *tenant.Service
	logger *slog.Logger
}

type createBody struct {
	Name        string `json:"name"`
	Index       int    `json:"index,omitempty"`
	TSIGSecret  string `json:"tsig_secret,omitempty"`
	StateSecret string `json:"state_secret,omitempty"`
	APIToken    string `json:"api_token,omitempty"`
}

type networkView struct {
	VRFVNI      int    `json:"vrf_vni"`
	VNetVNIBase int    `json:"vnet_vni_base"`
	Subnet      string `json:"subnet"`
	Gateway     string `json:"gateway"`
}

type fabricView struct {
	ControllerID string `json:"controller_id"`
	Node         string `json:"node"`
}

type dnsView struct {
	Zone          string `json:"zone"`
	ReverseZone   string `json:"reverse_zone"`
	UpdateServer  string `json:"update_server"`
	TSIGKeyName   string `json:"tsig_key_name"`
	TSIGAlgorithm string `json:"tsig_algorithm"`
	TSIGSecret    string `json:"tsig_secret,omitempty"`
}

type stateView struct {
	Endpoint  string `json:"endpoint"`
	Bucket    string `json:"bucket"`
	KeyPrefix string `json:"key_prefix"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key,omitempty"`
}

// stepView leaves out the step's error text: it can name backend hosts, and it
// is in the log and the database for the operator who needs it.
type stepView struct {
	Name      string    `json:"name"`
	OK        bool      `json:"ok"`
	UpdatedAt time.Time `json:"updated_at"`
}

type tenantView struct {
	Name      string      `json:"name"`
	Index     int         `json:"index"`
	Status    string      `json:"status"`
	Outcome   string      `json:"outcome,omitempty"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
	Network   networkView `json:"network"`
	Fabric    fabricView  `json:"fabric"`
	DNS       dnsView     `json:"dns"`
	State     stateView   `json:"state"`
	APIToken  string      `json:"api_token,omitempty"`
	// SecretsStored is false when the API holds secrets for this tenant that it
	// can no longer read - a rebuilt or rotated Transit key (ADR-0016 §6). The
	// tenant's own state is the authoritative copy (ADR-0015 §4), so this is how
	// a tenant learns it should supply them again. Without it nothing in a plan
	// differs and the resupply has to be remembered by an operator.
	SecretsStored bool       `json:"secrets_stored"`
	Steps         []stepView `json:"steps"`
}

// view renders a tenant. Secrets appear only when issued is non-nil, which is
// only for create and restore: that response is how they reach the tenant's state.
func (h *tenantHandlers) view(rec tenant.Record, outcome tenant.Outcome, issued *tenant.Issued) tenantView {
	site := h.svc.Site
	n := site.Numbering(rec.Index)
	v := tenantView{
		Name:      rec.Name,
		Index:     rec.Index,
		Status:    string(rec.Status),
		Outcome:   string(outcome),
		CreatedAt: rec.CreatedAt,
		UpdatedAt: rec.UpdatedAt,
		Network:   networkView{VRFVNI: n.VRFVNI, VNetVNIBase: n.VNetVNIBase, Subnet: n.Subnet, Gateway: n.Gateway},
		Fabric:    fabricView{ControllerID: site.ControllerID, Node: site.Node},
		DNS: dnsView{
			Zone:          site.Zone(rec.Name),
			ReverseZone:   n.ReverseZone,
			UpdateServer:  site.DNSUpdateServer,
			TSIGKeyName:   rec.Name,
			TSIGAlgorithm: "hmac-sha256",
		},
		State: stateView{
			Endpoint:  site.StateEndpoint,
			Bucket:    site.StateBucket,
			KeyPrefix: "tenants/" + rec.Name + "/",
			AccessKey: rec.Name,
		},
		SecretsStored: !rec.Secrets.Unreadable,
		Steps:         []stepView{},
	}
	if issued != nil {
		v.DNS.TSIGSecret = issued.TSIGSecret
		v.State.SecretKey = issued.StateSecret
		v.APIToken = issued.APIToken
	}
	for _, s := range rec.Steps {
		v.Steps = append(v.Steps, stepView{Name: s.Name, OK: s.OK, UpdatedAt: s.UpdatedAt})
	}
	return v
}

func (h *tenantHandlers) create(w http.ResponseWriter, r *http.Request) {
	var body createBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request body must be a JSON tenant"})
		return
	}

	// Who may create this name: the operator; the tenant itself, restoring or
	// resuming; or the holder of an enrollment token issued for it, which is
	// spent here.
	p := principalFrom(r.Context())
	switch {
	case p.operator:
	case p.tenant != "":
		if p.tenant != body.Name {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "a tenant token only creates its own tenant"})
			return
		}
	default:
		if err := h.svc.Redeem(r.Context(), p.presented, body.Name); err != nil {
			var step *tenant.StepError
			if errors.As(err, &step) {
				h.fail(w, err)
				return
			}
			auth.Deny(w)
			return
		}
	}

	res, err := h.svc.Create(r.Context(), tenant.CreateRequest(body))
	if err != nil {
		var step *tenant.StepError
		if errors.As(err, &step) && res.Record.Name != "" {
			// The tenant exists but is not finished. The body carries the
			// secrets anyway: the row holds them, and a caller that retries
			// resumes with the same ones.
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error":  step.Error(),
				"tenant": h.view(res.Record, res.Outcome, &res.Issued),
			})
			return
		}
		h.fail(w, err)
		return
	}

	status := http.StatusOK
	switch res.Outcome {
	case tenant.OutcomeCreated, tenant.OutcomeRestored, tenant.OutcomeReissued:
		status = http.StatusCreated
	}
	writeJSON(w, status, h.view(res.Record, res.Outcome, &res.Issued))
}

func (h *tenantHandlers) list(w http.ResponseWriter, r *http.Request) {
	recs, err := h.svc.List(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	out := make([]tenantView, 0, len(recs))
	for _, rec := range recs {
		out = append(out, h.view(rec, "", nil))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": out})
}

func (h *tenantHandlers) get(w http.ResponseWriter, r *http.Request) {
	rec, err := h.svc.Get(r.Context(), r.PathValue("name"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.view(rec, "", nil))
}

func (h *tenantHandlers) delete(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Delete(r.Context(), r.PathValue("name")); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *tenantHandlers) reconcile(w http.ResponseWriter, r *http.Request) {
	res, err := h.svc.Reconcile(r.Context(), r.PathValue("name"))
	if err != nil {
		var step *tenant.StepError
		if errors.As(err, &step) && res.Record.Name != "" {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": step.Error(), "tenant": h.view(res.Record, res.Outcome, nil)})
			return
		}
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.view(res.Record, res.Outcome, nil))
}

func (h *tenantHandlers) egress(w http.ResponseWriter, r *http.Request) {
	vrfs, err := h.svc.Egress(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"vrfs": vrfs})
}

// fail maps service errors to statuses. Anything unrecognised is a 500 whose
// detail goes to the log, never the body.
func (h *tenantHandlers) fail(w http.ResponseWriter, err error) {
	var inv *tenant.InvalidError
	var step *tenant.StepError
	switch {
	case errors.Is(err, tenant.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant not found"})
	case errors.Is(err, tenant.ErrExists):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "tenant already exists"})
	case errors.Is(err, tenant.ErrExhausted):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no free tenant index"})
	case errors.Is(err, tenant.ErrNoEnrollment):
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "enrollment is not configured on this API"})
	case errors.Is(err, tenant.ErrHasWorkloads):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "the tenant still has workloads; destroy them first"})
	case errors.Is(err, tenant.ErrWorkloadsExhausted):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no free workload ordinal"})
	case errors.Is(err, tenant.ErrFabricInUse):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "the fabric still carries this tenant's zone; destroy the tenant's resources first"})
	case errors.As(err, &inv):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": inv.Error()})
	case errors.As(err, &step):
		h.logger.Error("backend step failed", "step", step.Step, "err", step.Err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": step.Error()})
	default:
		h.logger.Error("request failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
}
