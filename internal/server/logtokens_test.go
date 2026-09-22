package server

import (
	"net/http"
	"testing"
)

// The tenant view carries the store's endpoint and the tenant's partition
// family for everyone, and the tokens only when they are issued.
func TestCreateReturnsLogTokensAndReconcileReturnsThemAgain(t *testing.T) {
	h, _, _ := tenantServer(t)

	rec, out := call(t, h, http.MethodPost, "/v1/tenants", `{"name":"eds"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %v", rec.Code, out)
	}
	ingest, _ := dig(out, "log", "ingest_token").(string)
	read, _ := dig(out, "log", "read_token").(string)
	if len(ingest) != 64 || len(read) != 64 {
		t.Fatalf("create returned log tokens %q and %q", ingest, read)
	}
	if acct, _ := dig(out, "log", "account_id").(float64); int(acct) != 1 {
		t.Errorf("log account_id = %v, want the tenant's index", dig(out, "log", "account_id"))
	}
	if h := dig(out, "log", "select_header"); h != "X-Deevnet-Partition" {
		t.Errorf("select_header = %v", h)
	}

	// A plain read never carries them.
	_, out = call(t, h, http.MethodGet, "/v1/tenants/eds", "")
	if dig(out, "log", "ingest_token") != nil || dig(out, "log", "read_token") != nil {
		t.Error("a GET returned the tenant's log tokens")
	}

	// A reconcile does, because that is how a tenant created before the store
	// existed is handed them - and still no TSIG secret or state key.
	rec, out = call(t, h, http.MethodPost, "/v1/tenants/eds/reconcile", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("reconcile: %d %v", rec.Code, out)
	}
	if got, _ := dig(out, "log", "ingest_token").(string); got != ingest {
		t.Errorf("reconcile returned ingest token %q, want the one issued", got)
	}
	if dig(out, "dns", "tsig_secret") != nil || dig(out, "state", "secret_key") != nil {
		t.Error("reconcile returned a secret the tenant's own state is authoritative for")
	}
}
