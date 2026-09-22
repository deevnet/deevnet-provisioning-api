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
