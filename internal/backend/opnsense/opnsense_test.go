package opnsense

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// fakeRouter answers the forwarding endpoints with the shapes OPNsense returns:
// the search rows were captured from dv02cor002p01 on 2026-09-17, and the
// result strings are ApiMutableModelControllerBase's and
// ApiMutableServiceControllerBase's.
type fakeRouter struct {
	mu           sync.Mutex
	rows         map[string]forwardRow // by uuid
	next         int
	reconfigures int
	calls        []string
}

func newFakeRouter() *fakeRouter { return &fakeRouter{rows: map[string]forwardRow{}} }

func (f *fakeRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, p, ok := r.BasicAuth(); !ok || u != "key" || p != "secret" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(r.Body)
	path := strings.TrimPrefix(r.URL.Path, "/api")
	f.calls = append(f.calls, path)
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }

	switch {
	case path == "/unbound/settings/searchForward":
		rows := []forwardRow{}
		for _, row := range f.rows {
			rows = append(rows, row)
		}
		// A DNS-over-TLS row shares the model and must be ignored.
		rows = append(rows, forwardRow{UUID: "dot-1", Type: "dot", Domain: "example.com", Server: "9.9.9.9", Enabled: "1"})
		reply(map[string]any{"rows": rows, "rowCount": len(rows), "total": len(rows), "current": 1})
	case path == "/unbound/settings/addForward" || strings.HasPrefix(path, "/unbound/settings/setForward/"):
		var in dotWrapper
		_ = json.Unmarshal(body, &in)
		if in.Dot.Type != "forward" || in.Dot.Domain == "" {
			reply(map[string]any{"result": "failed", "validations": map[string]string{"dot.type": "bad"}})
			return
		}
		uuid := strings.TrimPrefix(path, "/unbound/settings/setForward/")
		if path == "/unbound/settings/addForward" {
			f.next++
			uuid = "uuid-" + string(rune('0'+f.next))
		}
		f.rows[uuid] = forwardRow{UUID: uuid, Enabled: in.Dot.Enabled, Type: in.Dot.Type, Domain: in.Dot.Domain, Server: in.Dot.Server, Description: in.Dot.Description}
		reply(map[string]string{"result": "saved", "uuid": uuid})
	case strings.HasPrefix(path, "/unbound/settings/delForward/"):
		uuid := strings.TrimPrefix(path, "/unbound/settings/delForward/")
		if _, ok := f.rows[uuid]; !ok {
			reply(map[string]string{"result": "not found"})
			return
		}
		delete(f.rows, uuid)
		reply(map[string]string{"result": "deleted"})
	case path == "/unbound/service/reconfigure":
		f.reconfigures++
		reply(map[string]string{"status": "ok"})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func fwds() []tenant.Forward {
	return []tenant.Forward{
		{Domain: "tdemo.mobile.deevnet.net", Server: "10.20.25.21", Description: "Deevnet API - tenant tdemo (ADR-0015)"},
		{Domain: "130.20.10.in-addr.arpa", Server: "10.20.25.21", Description: "Deevnet API - tenant tdemo reverse (ADR-0015)"},
	}
}

func TestEnsureAddsOnceAndReconfiguresOnlyOnChange(t *testing.T) {
	f := newFakeRouter()
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := New(srv.URL+"/api", "key", "secret", false)
	ctx := context.Background()

	if err := c.Ensure(ctx, fwds()); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if len(f.rows) != 2 || f.reconfigures != 1 {
		t.Fatalf("rows %d reconfigures %d, want 2 and 1", len(f.rows), f.reconfigures)
	}
	if err := c.Ensure(ctx, fwds()); err != nil {
		t.Fatalf("ensure again: %v", err)
	}
	if len(f.rows) != 2 || f.reconfigures != 1 {
		t.Fatalf("second ensure changed something: rows %d reconfigures %d", len(f.rows), f.reconfigures)
	}
}

func TestEnsureAdoptsAnExistingRowAndOnlyFixesItsTarget(t *testing.T) {
	f := newFakeRouter()
	// eds's rows as the opnsense_dns role wrote them, one pointing at the
	// retired tenant DNS host.
	f.rows["e14d"] = forwardRow{UUID: "e14d", Enabled: "1", Type: "forward", Domain: "tdemo.mobile.deevnet.net", Server: "10.20.25.21", Description: "Ansible managed - tenant tdemo (ADR-0004)"}
	f.rows["3c4c"] = forwardRow{UUID: "3c4c", Enabled: "1", Type: "forward", Domain: "130.20.10.in-addr.arpa", Server: "10.20.99.30", Description: "Ansible managed - tenant tdemo reverse (ADR-0004)"}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := New(srv.URL+"/api", "key", "secret", false)

	if err := c.Ensure(context.Background(), fwds()); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if len(f.rows) != 2 || f.reconfigures != 1 {
		t.Fatalf("rows %d reconfigures %d, want the 2 existing rows and one reconfigure", len(f.rows), f.reconfigures)
	}
	if got := f.rows["3c4c"]; got.Server != "10.20.25.21" || got.Description != "Ansible managed - tenant tdemo reverse (ADR-0004)" {
		t.Fatalf("row = %+v, want the server corrected and the description kept", got)
	}
	for _, call := range f.calls {
		if strings.Contains(call, "setForward/e14d") {
			t.Error("a row that was already right was rewritten")
		}
	}
}

func TestRemoveDeletesOnlyTheTenantsRows(t *testing.T) {
	f := newFakeRouter()
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := New(srv.URL+"/api", "key", "secret", false)
	ctx := context.Background()

	if err := c.Ensure(ctx, append(fwds(), tenant.Forward{Domain: "eds.mobile.deevnet.net", Server: "10.20.25.21"})); err != nil {
		t.Fatal(err)
	}
	if err := c.Remove(ctx, []string{"tdemo.mobile.deevnet.net", "130.20.10.in-addr.arpa"}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if len(f.rows) != 1 || f.reconfigures != 2 {
		t.Fatalf("rows %v reconfigures %d, want eds's row left and a second reconfigure", f.rows, f.reconfigures)
	}
	if err := c.Remove(ctx, []string{"tdemo.mobile.deevnet.net"}); err != nil || f.reconfigures != 2 {
		t.Fatalf("removing an absent row: %v, reconfigures %d", err, f.reconfigures)
	}
}

func TestFailedResultIsAnError(t *testing.T) {
	f := newFakeRouter()
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := New(srv.URL+"/api", "key", "secret", false)
	bad := []tenant.Forward{{Domain: "", Server: "10.20.25.21"}}
	if err := c.Ensure(context.Background(), bad); err == nil || f.reconfigures != 0 {
		t.Fatalf("err = %v reconfigures %d, want a failure and no reconfigure", err, f.reconfigures)
	}
}

// Read-only against a real router: DEEVNET_TEST_OPNSENSE_URL (e.g.
// https://10.20.25.1/api), _KEY and _SECRET. It lists; it never writes.
func TestListAgainstARealRouter(t *testing.T) {
	u := os.Getenv("DEEVNET_TEST_OPNSENSE_URL")
	if u == "" {
		t.Skip("DEEVNET_TEST_OPNSENSE_URL not set")
	}
	c := New(u, os.Getenv("DEEVNET_TEST_OPNSENSE_KEY"), os.Getenv("DEEVNET_TEST_OPNSENSE_SECRET"), true)
	rows, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for d, r := range rows {
		t.Logf("%s -> %s (%s)", d, r.Server, r.Description)
	}
}
