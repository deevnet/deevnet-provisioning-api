package main

import (
	"strings"
	"testing"
)

func tokens(n int) (string, string) {
	return strings.Repeat(string(rune('a'+n)), 64), strings.Repeat(string(rune('A'+n)), 64)
}

func renderTwo(t *testing.T) string {
	t.Helper()
	edsIngest, edsRead := tokens(0)
	tdemoIngest, tdemoRead := tokens(1)
	doc, err := render(
		base{Backend: "http://127.0.0.1:9428/", OperatorToken: strings.Repeat("o", 64), BridgeToken: strings.Repeat("z", 64)},
		[]tenantFile{
			{Version: 1, Tenant: "eds", Index: 2, IngestToken: edsIngest, ReadToken: edsRead},
			{Version: 1, Tenant: "tdemo", Index: 1, IngestToken: tdemoIngest, ReadToken: tdemoRead},
		})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return string(doc)
}

func TestRenderCarriesEveryUser(t *testing.T) {
	got := renderTwo(t)
	for _, want := range []string{
		`- name: "operator-read"`,
		`- name: "ingest-eds"`,
		`- name: "read-eds"`,
		`- name: "ingest-tdemo"`,
		`- name: "read-tdemo"`,
		`- name: "mqtt-bridge"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered config has no %s\n%s", want, got)
		}
	}
}

// Every entry must set both partition headers. VictoriaLogs' default is the
// substrate partition, so an entry that forgot them would fail OPEN into
// substrate logs rather than closed - which is the failure this whole design
// exists to prevent.
func TestEveryRouteSetsBothPartitionHeaders(t *testing.T) {
	got := renderTwo(t)
	entries := strings.Count(got, "- src_paths:")
	accounts := strings.Count(got, `- "AccountID: `)
	projects := strings.Count(got, `- "ProjectID: `)
	if entries == 0 || accounts != entries || projects != entries {
		t.Fatalf("%d entries, %d AccountID headers, %d ProjectID headers", entries, accounts, projects)
	}
}

func TestIngestUserCanOnlyWriteItsOwnPartition(t *testing.T) {
	got := renderTwo(t)
	block := userBlock(t, got, "ingest-eds")
	if strings.Contains(block, "/select/") {
		t.Errorf("the ingest user can read:\n%s", block)
	}
	if !strings.Contains(block, `- "AccountID: 2"`) || !strings.Contains(block, `- "ProjectID: 0"`) {
		t.Errorf("the ingest user does not write (2,0):\n%s", block)
	}
	if strings.Contains(block, `- "AccountID: 1"`) {
		t.Errorf("the ingest user can reach another tenant's partition:\n%s", block)
	}
}

func TestReadUserCoversItsThreePartitionsAndNoOthers(t *testing.T) {
	got := renderTwo(t)
	block := userBlock(t, got, "read-eds")
	if strings.Contains(block, "/insert/") {
		t.Errorf("the read user can write:\n%s", block)
	}
	for _, p := range []string{`- "ProjectID: 0"`, `- "ProjectID: 1"`, `- "ProjectID: 2"`} {
		if !strings.Contains(block, p) {
			t.Errorf("the read user is missing %s:\n%s", p, block)
		}
	}
	if strings.Contains(block, `- "AccountID: 1"`) {
		t.Errorf("the read user can reach tenant 1's partitions:\n%s", block)
	}
}

// The selector entries have to come before the catch-all: vmauth takes the
// first entry that matches, and a leading catch-all would swallow every
// request and pin the reader to one partition.
func TestSelectorEntriesComeBeforeTheCatchAll(t *testing.T) {
	block := userBlock(t, renderTwo(t), "read-eds")
	firstSelector := strings.Index(block, "src_headers")
	entries := strings.Split(block, "- src_paths:")
	lastEntry := entries[len(entries)-1]
	if firstSelector == -1 {
		t.Fatalf("no selector entries at all:\n%s", block)
	}
	if strings.Contains(lastEntry, "src_headers") {
		t.Errorf("the last entry carries a selector, so there is no catch-all:\n%s", block)
	}
}

// The bridge holds one token and names a tenant per message. Its entries are
// what confine it: it can write each tenant's device partition and nothing
// else, and the selector never reaches the store.
func TestBridgeWritesOnlyDevicePartitions(t *testing.T) {
	block := userBlock(t, renderTwo(t), "mqtt-bridge")
	for _, want := range []string{
		`src_headers: ["X-Deevnet-Tenant: eds"]`,
		`src_headers: ["X-Deevnet-Tenant: tdemo"]`,
		`- "ProjectID: 2"`,
		`- "X-Deevnet-Tenant:"`,
	} {
		if !strings.Contains(block, want) {
			t.Errorf("the bridge user has no %s:\n%s", want, block)
		}
	}
	if strings.Contains(block, "/select/") {
		t.Errorf("the bridge can read:\n%s", block)
	}
	if strings.Contains(block, `- "ProjectID: 0"`) {
		t.Errorf("the bridge can write a tenant's own partition:\n%s", block)
	}
}

func TestBridgeUserIsOmittedWithoutAToken(t *testing.T) {
	ingest, read := tokens(0)
	doc, err := render(
		base{Backend: "http://127.0.0.1:9428/", OperatorToken: strings.Repeat("o", 64)},
		[]tenantFile{{Version: 1, Tenant: "eds", Index: 2, IngestToken: ingest, ReadToken: read}})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(string(doc), "mqtt-bridge") {
		t.Error("a bridge user was rendered with no bridge token")
	}
}

func TestRenderRefusesATenantFileItCannotTrust(t *testing.T) {
	cases := map[string]tenantFile{
		"a token that would break out of the document": {Version: 1, Tenant: "eds", Index: 2,
			IngestToken: strings.Repeat("a", 60) + `" #`, ReadToken: strings.Repeat("b", 64)},
		"the substrate's index": {Version: 1, Tenant: "eds", Index: 0,
			IngestToken: strings.Repeat("a", 64), ReadToken: strings.Repeat("b", 64)},
		"one token used for both": {Version: 1, Tenant: "eds", Index: 2,
			IngestToken: strings.Repeat("a", 64), ReadToken: strings.Repeat("a", 64)},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := render(base{Backend: "http://127.0.0.1:9428/", OperatorToken: strings.Repeat("o", 64)},
				[]tenantFile{f}); err == nil {
				t.Fatalf("rendered a config from %s", name)
			}
		})
	}
}

func TestRenderRefusesAnUnusableBase(t *testing.T) {
	ingest, read := tokens(0)
	fine := []tenantFile{{Version: 1, Tenant: "eds", Index: 2, IngestToken: ingest, ReadToken: read}}
	if _, err := render(base{OperatorToken: strings.Repeat("o", 64)}, fine); err == nil {
		t.Error("rendered a config with no backend")
	}
	if _, err := render(base{Backend: "http://127.0.0.1:9428/", OperatorToken: "short"}, fine); err == nil {
		t.Error("rendered a config with an operator token that is not one")
	}
}

// userBlock returns one user's stanza, up to the next user or the end.
func userBlock(t *testing.T, doc, name string) string {
	t.Helper()
	start := strings.Index(doc, `- name: "`+name+`"`)
	if start == -1 {
		t.Fatalf("no user %q in:\n%s", name, doc)
	}
	rest := doc[start+1:]
	if next := strings.Index(rest, `  - name: "`); next != -1 {
		return doc[start : start+1+next]
	}
	return doc[start:]
}

// The store runs with its delete API on (CHG-0065), so vmauth is what keeps it
// from every token: no rendered route may reach /delete/*, or anything but
// /select and /insert.
func TestNoRouteReachesTheDeleteAPI(t *testing.T) {
	doc := renderTwo(t)
	if strings.Contains(doc, "delete") {
		t.Fatal("the rendered configuration mentions delete")
	}
	for _, line := range strings.Split(doc, "\n") {
		if !strings.Contains(line, "src_paths") {
			continue
		}
		if !strings.Contains(line, `"/select/.*"`) && !strings.Contains(line, `"/insert/.*"`) {
			t.Errorf("a route outside /select and /insert: %s", strings.TrimSpace(line))
		}
	}
}

func renderTwoWithMetrics(t *testing.T) string {
	t.Helper()
	edsIngest, edsRead := tokens(0)
	tdemoIngest, tdemoRead := tokens(1)
	doc, err := render(
		base{Backend: "http://127.0.0.1:9428/", OperatorToken: strings.Repeat("o", 64), BridgeToken: strings.Repeat("z", 64),
			MetricsInsert: "http://127.0.0.1:8480/", MetricsSelect: "http://127.0.0.1:8481"},
		[]tenantFile{
			{Version: 1, Tenant: "eds", Index: 2, IngestToken: edsIngest, ReadToken: edsRead},
			{Version: 1, Tenant: "tdemo", Index: 1, IngestToken: tdemoIngest, ReadToken: tdemoRead},
		})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return string(doc)
}

// Without the metrics backends, nothing changes: a store with no metrics gets
// exactly the log routes it had.
func TestNoMetricsRoutesWithoutMetricsBackends(t *testing.T) {
	if doc := renderTwo(t); strings.Contains(doc, "/api/v1/") || strings.Contains(doc, "prometheus") {
		t.Fatalf("metrics routes rendered with no metrics backend:\n%s", doc)
	}
}

func TestRenderRefusesHalfAMetricsBackend(t *testing.T) {
	fine := []tenantFile{{Version: 1, Tenant: "eds", Index: 2, IngestToken: strings.Repeat("a", 64), ReadToken: strings.Repeat("b", 64)}}
	for name, b := range map[string]base{
		"insert only": {MetricsInsert: "http://127.0.0.1:8480"},
		"select only": {MetricsSelect: "http://127.0.0.1:8481"},
		"not http":    {MetricsInsert: "127.0.0.1:8480", MetricsSelect: "http://127.0.0.1:8481"},
	} {
		b.Backend, b.OperatorToken = "http://127.0.0.1:9428/", strings.Repeat("o", 64)
		if _, err := render(b, fine); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
}

func TestIngestUserWritesMetricsToItsOwnPartitionOnly(t *testing.T) {
	block := userBlock(t, renderTwoWithMetrics(t), "ingest-eds")
	if !strings.Contains(block, `url_prefix: "http://127.0.0.1:8480/insert/2:0/prometheus"`) {
		t.Errorf("the ingest user does not write metrics to (2,0):\n%s", block)
	}
	for _, bad := range []string{"/select/", "8481", "/insert/1:", "/insert/2:1", "/api/v1/query"} {
		if strings.Contains(block, bad) {
			t.Errorf("the ingest user's block contains %q:\n%s", bad, block)
		}
	}
}

func TestReadUserReadsItsTwoMetricsPartitionsAndNoOthers(t *testing.T) {
	block := userBlock(t, renderTwoWithMetrics(t), "read-eds")
	for _, want := range []string{
		`url_prefix: "http://127.0.0.1:8481/select/2:0/prometheus"`,
		`url_prefix: "http://127.0.0.1:8481/select/2:1/prometheus"`,
	} {
		if !strings.Contains(block, want) {
			t.Errorf("the read user has no %s:\n%s", want, block)
		}
	}
	for _, bad := range []string{"8480", "/select/2:2", "/select/1:", "/api/v1/write", "/api/v1/import"} {
		if strings.Contains(block, bad) {
			t.Errorf("the read user's block contains %q:\n%s", bad, block)
		}
	}
	// Its own (2,0) is the default, as for the logs: a metrics catch-all.
	var catchAll bool
	for _, e := range strings.Split(block, "- src_paths:")[1:] {
		if strings.Contains(e, "/api/v1/(query") && !strings.Contains(e, "src_headers") {
			if !strings.Contains(e, "/select/2:0/prometheus") {
				t.Errorf("the metrics catch-all is not (2,0):\n%s", e)
			}
			catchAll = true
		}
	}
	if !catchAll {
		t.Errorf("no metrics catch-all:\n%s", block)
	}
}

// The operator reads one tenant's metrics at a time, and only by naming it:
// there is no substrate metrics partition to fall back on.
func TestOperatorMetricsRoutesAreAllSelected(t *testing.T) {
	block := userBlock(t, renderTwoWithMetrics(t), "operator-read")
	n := 0
	for _, e := range strings.Split(block, "- src_paths:")[1:] {
		if !strings.Contains(e, "/api/v1/") {
			continue
		}
		n++
		if !strings.Contains(e, "src_headers") {
			t.Errorf("an operator metrics route with no selector:\n%s", e)
		}
	}
	if n != 4 {
		t.Errorf("%d operator metrics routes, want 4 (two tenants, two partitions)", n)
	}
}

// The store's multitenant and delete endpoints are always on (CHG-0070, Step
// 1). No route may name them, and every metrics route must be one of the
// fixed Prometheus paths, so no caller can reach them by its choice of path.
func TestNoMetricsRouteReachesMultitenantOrDelete(t *testing.T) {
	doc := renderTwoWithMetrics(t)
	for _, bad := range []string{"multitenant", "delete", "/admin/"} {
		if strings.Contains(doc, bad) {
			t.Errorf("the rendered configuration mentions %q", bad)
		}
	}
	for _, line := range strings.Split(doc, "\n") {
		if !strings.Contains(line, "src_paths") {
			continue
		}
		switch strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- src_paths:")) {
		case selectPaths, insertPaths, metricsWritePaths, metricsReadPaths:
		default:
			t.Errorf("an unexpected route: %s", strings.TrimSpace(line))
		}
	}
}
