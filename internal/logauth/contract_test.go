package logauth

import (
	"strings"
	"testing"
)

func validPut() Request {
	return Request{
		Version:     Version,
		Op:          OpPut,
		Tenant:      "eds",
		Index:       2,
		IngestToken: strings.Repeat("a", 64),
		ReadToken:   strings.Repeat("b", 64),
	}
}

func TestValidateAcceptsAWellFormedPut(t *testing.T) {
	if err := validPut().Validate(); err != nil {
		t.Fatalf("a well-formed put was refused: %v", err)
	}
}

func TestValidateRefuses(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Request)
		want string
	}{
		{"another version", func(r *Request) { r.Version = 2 }, "unsupported version"},
		{"an unknown op", func(r *Request) { r.Op = "patch" }, "unknown op"},
		{"a tenant name that is not one", func(r *Request) { r.Tenant = "EDS" }, "not a tenant name"},
		{"a tenant name over eight characters", func(r *Request) { r.Tenant = "ninechars" }, "not a tenant name"},
		// 0 is the substrate partition. A tenant that could claim index 0 could
		// write the substrate's own logs, which is the one thing ADR-0027 keeps
		// out of a tenant's reach.
		{"index zero", func(r *Request) { r.Index = 0 }, "outside 1.."},
		{"an index past the ceiling", func(r *Request) { r.Index = 64 }, "outside 1.."},
		{"a short token", func(r *Request) { r.IngestToken = "abc" }, "shorter than"},
		{"a token with YAML in it", func(r *Request) { r.IngestToken = strings.Repeat("a", 60) + `" #` }, "characters this writer will not"},
		{"a token with whitespace", func(r *Request) { r.ReadToken = " " + strings.Repeat("b", 63) }, "characters this writer will not"},
		{"one token used twice", func(r *Request) { r.ReadToken = r.IngestToken }, "the same value"},
		{"a missing read token", func(r *Request) { r.ReadToken = "" }, "shorter than"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := validPut()
			c.edit(&r)
			err := r.Validate()
			if err == nil {
				t.Fatalf("accepted %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refused %s with %q, which does not mention %q", c.name, err, c.want)
			}
		})
	}
}

func TestDeleteCarriesIdentityOnly(t *testing.T) {
	r := Request{Version: Version, Op: OpDelete, Tenant: "eds", Index: 2}
	if err := r.Validate(); err != nil {
		t.Fatalf("a delete was refused: %v", err)
	}
	// Tokens on a delete would mean the caller believes it is removing one
	// particular credential. It is not: it removes the tenant's users.
	r.IngestToken = strings.Repeat("a", 64)
	if err := r.Validate(); err == nil {
		t.Fatal("a delete carrying a token was accepted")
	}
}

func TestPartitionsAreDerivedFromTheIndex(t *testing.T) {
	r := validPut()
	if a, p := r.IngestPartition(); a != 2 || p != 0 {
		t.Fatalf("ingest partition = (%d,%d), want (2,0)", a, p)
	}
	if a, p := r.DevicePartition(); a != 2 || p != 2 {
		t.Fatalf("device partition = (%d,%d), want (2,2)", a, p)
	}
	got := r.ReadPartitions()
	want := [][2]int{{2, 0}, {2, 1}, {2, 2}}
	if len(got) != len(want) {
		t.Fatalf("read partitions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("read partitions = %v, want %v", got, want)
		}
	}
}

func TestUsernamesAreDerived(t *testing.T) {
	r := validPut()
	if r.IngestUser() != "ingest-eds" || r.ReadUser() != "read-eds" {
		t.Fatalf("users = %q and %q", r.IngestUser(), r.ReadUser())
	}
}

func TestDecodeRefusesUnknownFieldsAndTrailingContent(t *testing.T) {
	if _, err := Decode(strings.NewReader(`{"version":1,"op":"put","tenant":"eds","index":2,"partition":7}`)); err == nil {
		t.Fatal("an unknown field was accepted; a caller would believe something happened that did not")
	}
	body := `{"version":1,"op":"delete","tenant":"eds","index":2}`
	if _, err := Decode(strings.NewReader(body + body)); err == nil {
		t.Fatal("trailing content was accepted; this protocol is one request and one answer")
	}
	if _, err := Decode(strings.NewReader(body)); err != nil {
		t.Fatalf("a single request was refused: %v", err)
	}
}
