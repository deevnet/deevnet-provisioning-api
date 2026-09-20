package brokeracct

import (
	"strings"
	"testing"
)

// A real bcrypt hash, so the fixture cannot drift from what bcrypt emits.
const goodHash = "$2a$12$vkf24cu3BovLL9fMP38C0.WOlTeHB9aEU1Vp3p4JP4OErWDg7AdmG"

func put() Request {
	return Request{
		Version: Version, Op: OpPut, Tenant: "eds", Account: "lightd",
		PasswordHash: goodHash,
		Publish:      []string{"eds/lightstand/+/scene"},
		Subscribe:    []string{"eds/lightstand/+/status"},
	}
}

func TestAValidPutIsAccepted(t *testing.T) {
	if err := put().Validate(); err != nil {
		t.Fatalf("a valid request was refused: %v", err)
	}
}

// The three things the caller does not get to choose. If any of these ever
// becomes a field, a caller can name another tenant's account.
func TestIdentityIsDerivedNotAccepted(t *testing.T) {
	r := put()
	if got := r.Username(); got != "eds-lightd" {
		t.Errorf("username = %q, want eds-lightd", got)
	}
	if r.Mountpoint() != "" {
		t.Errorf("mountpoint = %q, want empty (ADR-0012 §10)", r.Mountpoint())
	}
	if r.ClientID() != "*" {
		t.Errorf("client_id = %q, want * (ADR-0012 §10)", r.ClientID())
	}
}

// Supplying a username must be refused outright rather than ignored. A caller
// that sends one believes it chose the name.
func TestSuppliedUsernameIsRefused(t *testing.T) {
	body := `{"version":1,"op":"put","tenant":"eds","account":"lightd",
	          "username":"tdemo-anything","password_hash":"` + goodHash + `",
	          "publish":["eds/a"],"subscribe":["eds/a"]}`
	if _, err := Decode(strings.NewReader(body)); err == nil {
		t.Fatal("a request supplying its own username was accepted")
	}
}

func TestUnknownFieldIsRefused(t *testing.T) {
	body := `{"version":1,"op":"put","tenant":"eds","account":"lightd","mountpoint":"other",
	          "password_hash":"` + goodHash + `","publish":["eds/a"],"subscribe":["eds/a"]}`
	if _, err := Decode(strings.NewReader(body)); err == nil {
		t.Fatal("an unknown field was silently ignored")
	}
}

func TestTrailingContentIsRefused(t *testing.T) {
	body := `{"version":1,"op":"delete","tenant":"eds","account":"lightd"} {"version":1}`
	if _, err := Decode(strings.NewReader(body)); err == nil {
		t.Fatal("trailing content was accepted; this protocol is one request and one answer")
	}
}

func TestOversizedRequestIsRefused(t *testing.T) {
	huge := `{"version":1,"op":"put","tenant":"eds","account":"a","password_hash":"` +
		strings.Repeat("x", MaxRequestBytes+100) + `"}`
	if _, err := Decode(strings.NewReader(huge)); err == nil {
		t.Fatal("an oversized request was read in full")
	}
}

func TestVersionMismatchIsRefused(t *testing.T) {
	r := put()
	r.Version = 2
	if err := r.Validate(); err == nil {
		t.Fatal("a future version was accepted; a mismatch must be said out loud")
	}
}

// The prefix is what confines a tenant. This is the check that matters most.
func TestPatternsOutsideTheTenantPrefixAreRefused(t *testing.T) {
	for _, bad := range []string{
		"tdemo/lightstand/+/scene", // another tenant outright
		"/eds/a",                   // leading slash puts eds at the second level
		"edsx/a",                   // prefix-alike, not the prefix
		"eds",                      // the name without the separator
		"$SYS/#",
		"#",
	} {
		r := put()
		r.Publish = []string{bad}
		if err := r.Validate(); err == nil {
			t.Errorf("publish pattern %q was accepted outside the prefix", bad)
		}
		r = put()
		r.Subscribe = []string{bad}
		if err := r.Validate(); err == nil {
			t.Errorf("subscribe pattern %q was accepted outside the prefix", bad)
		}
	}
}

// An error must not reflect the caller's own string back over the wire.
func TestPrefixErrorDoesNotEchoThePattern(t *testing.T) {
	r := put()
	r.Publish = []string{"tdemo/secret-looking-thing"}
	err := r.Validate()
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if strings.Contains(err.Error(), "secret-looking-thing") {
		t.Errorf("the error echoed the caller's pattern: %v", err)
	}
}

func TestWildcardRules(t *testing.T) {
	ok := []string{"eds/a/+/c", "eds/#", "eds/a/#", "eds/+", "eds/+/+"}
	bad := []string{"eds/a+/c", "eds/+x", "eds/#/more", "eds/a#", "eds/x#y"}
	for _, p := range ok {
		r := put()
		r.Publish = []string{p}
		if err := r.Validate(); err != nil {
			t.Errorf("valid filter %q refused: %v", p, err)
		}
	}
	for _, p := range bad {
		r := put()
		r.Publish = []string{p}
		if err := r.Validate(); err == nil {
			t.Errorf("malformed filter %q accepted", p)
		}
	}
}

func TestTemplateVariablesAreRefused(t *testing.T) {
	r := put()
	r.Publish = []string{"eds/%u/scene"}
	if err := r.Validate(); err == nil {
		t.Fatal("a VerneMQ template variable was accepted")
	}
}

func TestPasswordHashMustBeBcrypt(t *testing.T) {
	for _, bad := range []string{"", "plaintext", "$2b$12$" + strings.Repeat("x", 53), goodHash + "x", goodHash[:59]} {
		r := put()
		r.PasswordHash = bad
		if err := r.Validate(); err == nil {
			t.Errorf("password_hash %q was accepted", bad)
		}
	}
}

func TestDeleteCarriesIdentityOnly(t *testing.T) {
	d := Request{Version: Version, Op: OpDelete, Tenant: "eds", Account: "lightd"}
	if err := d.Validate(); err != nil {
		t.Fatalf("a valid delete was refused: %v", err)
	}
	d.PasswordHash = goodHash
	if err := d.Validate(); err == nil {
		t.Error("a delete carrying a password_hash was accepted")
	}
	d = Request{Version: Version, Op: OpDelete, Tenant: "eds", Account: "lightd", Publish: []string{"eds/a"}}
	if err := d.Validate(); err == nil {
		t.Error("a delete carrying publish patterns was accepted")
	}
}

func TestNamesAreBounded(t *testing.T) {
	for _, tn := range []string{"", "TOOLONGNAME", "toolongtenant", "1eds", "Eds", "ed_s"} {
		r := put()
		r.Tenant = tn
		if err := r.Validate(); err == nil {
			t.Errorf("tenant %q accepted", tn)
		}
	}
	for _, ac := range []string{"", strings.Repeat("a", 21), "1x", "X", "a_b", "trailing-"} {
		r := put()
		r.Account = ac
		if err := r.Validate(); err == nil {
			t.Errorf("account %q accepted", ac)
		}
	}
}

func TestPatternCountAndLengthAreBounded(t *testing.T) {
	r := put()
	for i := 0; i <= maxPatterns; i++ {
		r.Publish = append(r.Publish, "eds/a")
	}
	if err := r.Validate(); err == nil {
		t.Error("an unbounded number of patterns was accepted")
	}
	r = put()
	r.Publish = []string{"eds/" + strings.Repeat("a", maxPattern)}
	if err := r.Validate(); err == nil {
		t.Error("an over-long pattern was accepted")
	}
	r = put()
	r.Publish = nil
	if err := r.Validate(); err == nil {
		t.Error("a put with no publish patterns was accepted")
	}
}

func TestOpMustBeKnown(t *testing.T) {
	for _, op := range []string{"", "PUT", "drop", "select"} {
		r := put()
		r.Op = op
		if err := r.Validate(); err == nil {
			t.Errorf("op %q accepted", op)
		}
	}
}
