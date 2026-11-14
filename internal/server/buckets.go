package server

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Tenant buckets and their keys (ADR-0026 §3, CHG-0069). A tenant's own, or
// the operator's on its behalf: ownTenant, as for broker accounts, because a
// key is a credential.
func bucketRoutes(mux *http.ServeMux, h *tenantHandlers) {
	mux.HandleFunc("POST /v1/tenants/{name}/buckets", h.ownTenant(h.createBucket))
	mux.HandleFunc("GET /v1/tenants/{name}/buckets", h.ownTenant(h.listBuckets))
	mux.HandleFunc("GET /v1/tenants/{name}/buckets/{bucket}", h.ownTenant(h.getBucket))
	mux.HandleFunc("PUT /v1/tenants/{name}/buckets/{bucket}", h.ownTenant(h.updateBucket))
	mux.HandleFunc("DELETE /v1/tenants/{name}/buckets/{bucket}", h.ownTenant(h.deleteBucket))
	mux.HandleFunc("POST /v1/tenants/{name}/buckets/{bucket}/keys", h.ownTenant(h.createBucketKey))
	mux.HandleFunc("GET /v1/tenants/{name}/buckets/{bucket}/keys", h.ownTenant(h.listBucketKeys))
	mux.HandleFunc("GET /v1/tenants/{name}/buckets/{bucket}/keys/{key}", h.ownTenant(h.getBucketKey))
	mux.HandleFunc("DELETE /v1/tenants/{name}/buckets/{bucket}/keys/{key}", h.ownTenant(h.deleteBucketKey))
}

// bucketLifecycleView is a bucket's lifecycle rules, in days; 0 is none.
type bucketLifecycleView struct {
	ExpireDays           int `json:"expire_days"`
	NoncurrentExpireDays int `json:"noncurrent_expire_days"`
}

type bucketBody struct {
	Name       string              `json:"name"`
	QuotaGB    int                 `json:"quota_gb"`
	Versioning bool                `json:"versioning"`
	Lifecycle  bucketLifecycleView `json:"lifecycle"`
	PublicRead bool                `json:"public_read"`
}

// bucketUpdateBody is bucketBody without the name, which the path carries
// and which cannot change.
type bucketUpdateBody struct {
	QuotaGB    int                 `json:"quota_gb"`
	Versioning bool                `json:"versioning"`
	Lifecycle  bucketLifecycleView `json:"lifecycle"`
	PublicRead bool                `json:"public_read"`
}

type bucketView struct {
	Name string `json:"name"`
	// Bucket is the store's name for it: "<tenant>-<name>".
	Bucket     string              `json:"bucket"`
	Endpoint   string              `json:"endpoint"`
	QuotaGB    int                 `json:"quota_gb"`
	Versioning bool                `json:"versioning"`
	Lifecycle  bucketLifecycleView `json:"lifecycle"`
	PublicRead bool                `json:"public_read"`
	Status     string              `json:"status"`
	// Key is the default key, on the create response only.
	Key *bucketKeyView `json:"key,omitempty"`
}

type bucketKeyBody struct {
	Name   string `json:"name"`
	Access string `json:"access"`
}

type bucketKeyView struct {
	Name      string `json:"name"`
	Access    string `json:"access"`
	AccessKey string `json:"access_key"`
	// SecretKey is on a create response only. A read never carries it.
	SecretKey string `json:"secret_key,omitempty"`
}

func (h *tenantHandlers) bucketViewOf(b tenant.Bucket) bucketView {
	return bucketView{
		Name:       b.Name,
		Bucket:     b.StoreName(),
		Endpoint:   h.svc.BucketEndpoint,
		QuotaGB:    b.QuotaGB,
		Versioning: b.Versioning,
		Lifecycle:  bucketLifecycleView{ExpireDays: b.ExpireDays, NoncurrentExpireDays: b.NoncurrentExpireDays},
		PublicRead: b.PublicRead,
		Status:     string(b.Status),
	}
}

// bucketKeyViewOf renders a key. issued is true only on a create.
func bucketKeyViewOf(k tenant.BucketKey, issued bool) bucketKeyView {
	v := bucketKeyView{Name: k.Name, Access: k.Access, AccessKey: k.AccessKey}
	if issued {
		v.SecretKey = k.SecretKey
	}
	return v
}

func (h *tenantHandlers) createBucket(w http.ResponseWriter, r *http.Request) {
	var body bucketBody
	if !decode(w, r, &body) {
		return
	}
	b, k, err := h.svc.CreateBucket(r.Context(), r.PathValue("name"), tenant.BucketRequest{
		Name: body.Name, QuotaGB: body.QuotaGB, Versioning: body.Versioning,
		ExpireDays: body.Lifecycle.ExpireDays, NoncurrentExpireDays: body.Lifecycle.NoncurrentExpireDays,
		PublicRead: body.PublicRead,
	})
	v := h.bucketViewOf(b)
	if k.AccessKey != "" {
		kv := bucketKeyViewOf(k, true)
		v.Key = &kv
	}
	if err != nil {
		var step *tenant.StepError
		if errors.As(err, &step) && b.Name != "" {
			// The rows exist and the store did not take them. The partial
			// bucket goes back with its key's secret; the same call resumes
			// it with the same key.
			h.logger.Error("backend step failed", "step", step.Step, "err", step.Err)
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": step.Error(), "bucket": v})
			return
		}
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (h *tenantHandlers) listBuckets(w http.ResponseWriter, r *http.Request) {
	buckets, err := h.svc.ListBuckets(r.Context(), r.PathValue("name"))
	if err != nil {
		h.fail(w, err)
		return
	}
	out := make([]bucketView, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, h.bucketViewOf(b))
	}
	writeJSON(w, http.StatusOK, map[string]any{"buckets": out})
}

func (h *tenantHandlers) getBucket(w http.ResponseWriter, r *http.Request) {
	b, err := h.svc.GetBucket(r.Context(), r.PathValue("name"), r.PathValue("bucket"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.bucketViewOf(b))
}

func (h *tenantHandlers) updateBucket(w http.ResponseWriter, r *http.Request) {
	var body bucketUpdateBody
	if !decode(w, r, &body) {
		return
	}
	b, err := h.svc.UpdateBucket(r.Context(), r.PathValue("name"), r.PathValue("bucket"), tenant.BucketRequest{
		QuotaGB: body.QuotaGB, Versioning: body.Versioning,
		ExpireDays: body.Lifecycle.ExpireDays, NoncurrentExpireDays: body.Lifecycle.NoncurrentExpireDays,
		PublicRead: body.PublicRead,
	})
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.bucketViewOf(b))
}

func (h *tenantHandlers) deleteBucket(w http.ResponseWriter, r *http.Request) {
	force := false
	if v := r.URL.Query().Get("force"); v != "" {
		var err error
		if force, err = strconv.ParseBool(v); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "force must be true or false"})
			return
		}
	}
	if err := h.svc.DeleteBucket(r.Context(), r.PathValue("name"), r.PathValue("bucket"), force); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *tenantHandlers) createBucketKey(w http.ResponseWriter, r *http.Request) {
	var body bucketKeyBody
	if !decode(w, r, &body) {
		return
	}
	k, err := h.svc.CreateBucketKey(r.Context(), r.PathValue("name"), r.PathValue("bucket"), tenant.BucketKeyRequest(body))
	if err != nil {
		var step *tenant.StepError
		if errors.As(err, &step) && k.AccessKey != "" {
			h.logger.Error("backend step failed", "step", step.Step, "err", step.Err)
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": step.Error(), "key": bucketKeyViewOf(k, true)})
			return
		}
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, bucketKeyViewOf(k, true))
}

func (h *tenantHandlers) listBucketKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.svc.ListBucketKeys(r.Context(), r.PathValue("name"), r.PathValue("bucket"))
	if err != nil {
		h.fail(w, err)
		return
	}
	out := make([]bucketKeyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, bucketKeyViewOf(k, false))
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

func (h *tenantHandlers) getBucketKey(w http.ResponseWriter, r *http.Request) {
	k, err := h.svc.GetBucketKey(r.Context(), r.PathValue("name"), r.PathValue("bucket"), r.PathValue("key"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, bucketKeyViewOf(k, false))
}

func (h *tenantHandlers) deleteBucketKey(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.DeleteBucketKey(r.Context(), r.PathValue("name"), r.PathValue("bucket"), r.PathValue("key")); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
