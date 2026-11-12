package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/logauth"
)

// fakeStore answers the delete API the way VictoriaLogs v1.52 does: run_task
// takes the tenant from the headers, and a task stays listed for a while.
type fakeStore struct {
	mu      sync.Mutex
	started []string // "account:project"
	active  []deleteTask
	polls   int
}

func (f *fakeStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/delete/run_task":
		_ = r.ParseForm()
		if r.Method != http.MethodPost || r.Form.Get("filter") != "*" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		key := r.Header.Get("AccountID") + ":" + r.Header.Get("ProjectID")
		f.started = append(f.started, key)
		id := fmt.Sprintf("task-%d", len(f.started))
		var t deleteTask
		t.TaskID, t.Filter = id, "*"
		var a, p int
		fmt.Sscanf(key, "%d:%d", &a, &p)
		t.TenantIDs = append(t.TenantIDs, struct {
			AccountID int `json:"account_id"`
			ProjectID int `json:"project_id"`
		}{a, p})
		f.active = append(f.active, t)
		fmt.Fprintf(w, `{"task_id":%q}`, id)
	case "/delete/active_tasks":
		f.polls++
		// Tasks finish after a couple of polls.
		if f.polls > 2 {
			f.active = nil
		}
		_ = json.NewEncoder(w).Encode(append([]deleteTask{}, f.active...))
	default:
		http.NotFound(w, r)
	}
}

func purgeConfig(t *testing.T, storeURL string, files ...tenantFile) config {
	t.Helper()
	dir := t.TempDir()
	for _, f := range files {
		b, _ := json.Marshal(f)
		if err := os.WriteFile(filepath.Join(dir, f.Tenant+".json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return config{UsersDir: dir, StoreURL: storeURL}
}

func purgeReq(name string, index int) logauth.Request {
	return logauth.Request{Version: logauth.Version, Op: logauth.OpPurge, Tenant: name, Index: index}
}

func TestPurgeDeletesTheThreePartitionsAndWaits(t *testing.T) {
	f := &fakeStore{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	ingest, read := tokens(0)
	cfg := purgeConfig(t, srv.URL, tenantFile{Version: 1, Tenant: "eds", Index: 2, IngestToken: ingest, ReadToken: read})

	if err := purge(context.Background(), cfg, purgeReq("trm", 5)); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if got := strings.Join(f.started, ","); got != "5:0,5:1,5:2" {
		t.Errorf("deleted partitions %s, want 5:0,5:1,5:2 and nothing else", got)
	}
	if f.polls < 3 {
		t.Errorf("returned after %d polls, before the tasks finished", f.polls)
	}
}

func TestPurgeIsRefusedWhileUsersNameTheIndex(t *testing.T) {
	f := &fakeStore{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	ingest, read := tokens(0)

	// The tenant's own users still there: its delete has not removed them.
	cfg := purgeConfig(t, srv.URL, tenantFile{Version: 1, Tenant: "trm", Index: 5, IngestToken: ingest, ReadToken: read})
	if err := purge(context.Background(), cfg, purgeReq("trm", 5)); !errors.Is(err, errPurgeRefused) {
		t.Errorf("own users present: %v, want refused", err)
	}
	// Another tenant holds the index: the lines may be its own.
	cfg = purgeConfig(t, srv.URL, tenantFile{Version: 1, Tenant: "newt", Index: 5, IngestToken: ingest, ReadToken: read})
	if err := purge(context.Background(), cfg, purgeReq("trm", 5)); !errors.Is(err, errPurgeRefused) {
		t.Errorf("index held by another tenant: %v, want refused", err)
	}
	// Not configured to purge.
	cfg = purgeConfig(t, "")
	if err := purge(context.Background(), cfg, purgeReq("trm", 5)); !errors.Is(err, errPurgeRefused) {
		t.Errorf("no store_url: %v, want refused", err)
	}
	if len(f.started) != 0 {
		t.Errorf("a refused purge started tasks: %v", f.started)
	}
}

func TestPurgeWaitsForATaskAlreadyRunning(t *testing.T) {
	f := &fakeStore{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	// A previous, interrupted purge left partition 5:1 running.
	var t1 deleteTask
	t1.TaskID, t1.Filter = "earlier", "*"
	t1.TenantIDs = append(t1.TenantIDs, struct {
		AccountID int `json:"account_id"`
		ProjectID int `json:"project_id"`
	}{5, 1})
	f.active = []deleteTask{t1}

	if err := purge(context.Background(), purgeConfig(t, srv.URL), purgeReq("trm", 5)); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if got := strings.Join(f.started, ","); got != "5:0,5:2" {
		t.Errorf("started %s, want 5:0,5:2: the running task is waited for, not repeated", got)
	}
}

func TestPurgeGivesUpAtItsDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/delete/run_task":
			io.WriteString(w, `{"task_id":"stuck"}`)
		default:
			io.WriteString(w, `[{"task_id":"stuck","filter":"*","tenant_ids":[{"account_id":5,"project_id":0}]}]`)
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if err := purge(ctx, purgeConfig(t, srv.URL), purgeReq("trm", 5)); err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stuck task: %v, want the deadline", err)
	}
}

// Against the VictoriaLogs the site runs: DEEVNET_TEST_VL_URL names one started
// with -delete.enable (`make test-integration` starts v1.52.0). Two tenants'
// lines in all three partitions; the purge removes one tenant's and only those.
func TestPurgeAgainstVictoriaLogs(t *testing.T) {
	u := os.Getenv("DEEVNET_TEST_VL_URL")
	if u == "" {
		t.Skip("DEEVNET_TEST_VL_URL not set")
	}
	ingest := func(account, project int, msg string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, u+"/insert/jsonline?_stream_fields=app",
			strings.NewReader(fmt.Sprintf(`{"_msg":%q,"app":"a%d"}`+"\n", msg, account)))
		req.Header.Set("Content-Type", "application/stream+json")
		req.Header.Set("AccountID", fmt.Sprint(account))
		req.Header.Set("ProjectID", fmt.Sprint(project))
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("ingest: %v %v", err, resp)
		}
		resp.Body.Close()
	}
	count := func(account, project int) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, u+"/select/logsql/query", strings.NewReader("query=*"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("AccountID", fmt.Sprint(account))
		req.Header.Set("ProjectID", fmt.Sprint(project))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		n := 0
		for _, line := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(line) != "" {
				n++
			}
		}
		return n
	}
	for p := 0; p < 3; p++ {
		for n := 0; n < 3; n++ {
			ingest(41, p, fmt.Sprintf("deleted-tenant-%d-%d", p, n))
			ingest(42, p, fmt.Sprintf("neighbour-%d-%d", p, n))
		}
	}
	// Ingested lines become searchable within a second or so.
	deadline := time.Now().Add(10 * time.Second)
	for count(41, 2) < 3 || count(42, 2) < 3 {
		if time.Now().After(deadline) {
			t.Fatal("ingested lines never became searchable")
		}
		time.Sleep(200 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := purge(ctx, purgeConfig(t, u), purgeReq("tgone", 41)); err != nil {
		t.Fatalf("purge: %v", err)
	}
	for p := 0; p < 3; p++ {
		if n := count(41, p); n != 0 {
			t.Errorf("partition 41:%d has %d lines after the purge", p, n)
		}
		if n := count(42, p); n != 3 {
			t.Errorf("the neighbour's partition 42:%d has %d lines, want 3 untouched", p, n)
		}
	}
	// Again: nothing to delete is still success.
	if err := purge(ctx, purgeConfig(t, u), purgeReq("tgone", 41)); err != nil {
		t.Fatalf("purge again: %v", err)
	}
}
