package server

import (
	"errors"
	"net/http"
	"testing"
)

func TestBrokerAccountCreateReturnsTheCredential(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	call(t, h, http.MethodPost, "/v1/tenants/eds/devices", `{"name":"stand-1","trust_class":"iot"}`)

	rec, body := callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/broker-accounts",
		`{"name":"lightd","device":"stand-1","publish":["lightstand/+/scene"],"subscribe":["lightstand/+/state"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	// The username is derived and reported, so a tenant can configure a device
	// without knowing the derivation and without being able to choose it.
	if body["username"] != "eds-lightd" {
		t.Errorf("username = %v", body["username"])
	}
	if body["password"] == nil || body["password"] == "" {
		t.Error("the create response carried no password; the tenant's state is the only copy")
	}
	if body["status"] != "ready" {
		t.Errorf("status = %v", body["status"])
	}
}

// ADR-0012 §10: the API writes the prefix. What goes back is what the broker
// will enforce, which is deliberately not what the tenant sent - seeing the
// prefix is how a tenant can tell confinement was applied.
func TestBrokerAccountPatternsComeBackPrefixed(t *testing.T) {
	h, _, b := tenantServer(t)
	call(t, h, http.MethodPost, "/v1/tenants", `{"name":"eds"}`)

	_, body := call(t, h, http.MethodPost, "/v1/tenants/eds/broker-accounts",
		`{"name":"lightd","publish":["lightstand/+/scene"]}`)
	pub, _ := body["publish"].([]any)
	if len(pub) != 1 || pub[0] != "eds/lightstand/+/scene" {
		t.Errorf("publish = %v, want the tenant prefix written by the API", body["publish"])
	}
	// And what the writer was actually handed matches, so the prefix is not
	// merely cosmetic in the response.
	if got := b.BrokerAccounts["eds/lightd"].Publish; len(got) != 1 || got[0] != "eds/lightstand/+/scene" {
		t.Errorf("the writer was handed %v", got)
	}
	// An account with no subscribe renders as [], not null: "may publish, may
	// not subscribe" should not look like a field the tenant has to guess at.
	if sub, ok := body["subscribe"].([]any); !ok || len(sub) != 0 {
		t.Errorf("subscribe = %v, want []", body["subscribe"])
	}
}

// A tenant cannot reach outside its own prefix, whatever it sends.
//
// Naming another tenant does not escape - "tdemo/secrets/#" becomes
// "eds/tdemo/secrets/#", a topic inside eds that happens to be named after
// someone else, which grants nothing. What IS refused is a pattern the API
// cannot prefix meaningfully, or one whose wildcards do not mean what the
// tenant wrote.
func TestBrokerAccountPatternsCannotEscapeTheTenant(t *testing.T) {
	h, _, b := tenantServer(t)
	call(t, h, http.MethodPost, "/v1/tenants", `{"name":"eds"}`)

	rec, body := call(t, h, http.MethodPost, "/v1/tenants/eds/broker-accounts",
		`{"name":"nosy","subscribe":["tdemo/secrets/#"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	sub, _ := body["subscribe"].([]any)
	if len(sub) != 1 || sub[0] != "eds/tdemo/secrets/#" {
		t.Errorf("subscribe = %v; naming another tenant must land inside eds", body["subscribe"])
	}

	// A subscription wider than the tenant - the one thing that would escape.
	for _, bad := range []string{"#", "+/#", "/absolute", "$SYS/#", "%u/x"} {
		rec, _ := call(t, h, http.MethodPost, "/v1/tenants/eds/broker-accounts",
			`{"name":"nosy2","subscribe":["`+bad+`"]}`)
		// "#" and "+/#" are relative, so they prefix to eds/# and eds/+/# and
		// are legitimately allowed: they are the whole of the tenant's own
		// tree and no more. The rest cannot be prefixed into anything the
		// tenant meant.
		switch bad {
		case "#", "+/#":
			if rec.Code != http.StatusCreated {
				t.Errorf("subscribe %q = %d; a tenant may take its whole tree", bad, rec.Code)
			}
		default:
			if rec.Code != http.StatusBadRequest {
				t.Errorf("subscribe %q = %d, want 400", bad, rec.Code)
			}
		}
	}
	// Nothing the broker was handed sits outside the prefix.
	for key, a := range b.BrokerAccounts {
		for _, p := range append(append([]string{}, a.Publish...), a.Subscribe...) {
			if len(p) < 4 || p[:4] != "eds/" {
				t.Errorf("%s was granted %q, outside the tenant prefix", key, p)
			}
		}
	}
}

func TestBrokerAccountRouteIsImplemented(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")

	rec, _ := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/broker-accounts", "")
	if rec.Code == http.StatusNotImplemented {
		t.Fatal("broker accounts still answer 501")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

// A read must never carry the password. The API holds the hash, not the
// plaintext, so there is nothing it could honestly return - and a read that
// returned one would be a second copy of a credential that is supposed to
// exist only in the tenant's own state.
func TestBrokerAccountReadNeverCarriesThePassword(t *testing.T) {
	h, _, _ := tenantServer(t)
	call(t, h, http.MethodPost, "/v1/tenants", `{"name":"eds"}`)
	call(t, h, http.MethodPost, "/v1/tenants/eds/broker-accounts", `{"name":"lightd","publish":["lightstand/+/scene"]}`)

	_, body := call(t, h, http.MethodGet, "/v1/tenants/eds/broker-accounts/lightd", "")
	if _, present := body["password"]; present {
		t.Errorf("a read returned a password: %v", body)
	}
	_, list := call(t, h, http.MethodGet, "/v1/tenants/eds/broker-accounts", "")
	accounts, _ := list["broker_accounts"].([]any)
	if len(accounts) != 1 {
		t.Fatalf("list = %v", list)
	}
	if a, _ := accounts[0].(map[string]any); a["password"] != nil {
		t.Errorf("a list returned a password: %v", a)
	}
}

// Re-applying an unchanged account returns no password, because the API does
// not hold the plaintext. The provider keeps the one in its own state.
func TestBrokerAccountReapplyReturnsNoPassword(t *testing.T) {
	h, _, _ := tenantServer(t)
	call(t, h, http.MethodPost, "/v1/tenants", `{"name":"eds"}`)
	_, first := call(t, h, http.MethodPost, "/v1/tenants/eds/broker-accounts", `{"name":"lightd","publish":["lightstand/+/scene"]}`)
	if first["password"] == nil {
		t.Fatal("the first create returned no password")
	}

	rec, second := call(t, h, http.MethodPost, "/v1/tenants/eds/broker-accounts", `{"name":"lightd","publish":["lightstand/+/scene"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if second["password"] != nil {
		t.Errorf("a re-apply minted a second password; every device holding the first would be stranded")
	}
}

// The writer failing is the ambiguous case the retry path exists for: the row
// is written, the broker may or may not have the account. The password comes
// back so the retry supplies the same one.
func TestBrokerAccountWriterFailureReturnsThePasswordWith502(t *testing.T) {
	h, _, b := tenantServer(t)
	call(t, h, http.MethodPost, "/v1/tenants", `{"name":"eds"}`)
	b.BrokerErr = errors.New("the writer did not answer")

	rec, body := call(t, h, http.MethodPost, "/v1/tenants/eds/broker-accounts", `{"name":"lightd","publish":["lightstand/+/scene"]}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("%d %s, want 502", rec.Code, rec.Body.String())
	}
	acct, _ := body["broker_account"].(map[string]any)
	if acct["password"] == nil || acct["password"] == "" {
		t.Fatal("a failed write returned no password; the retry would mint a second one")
	}
	// The error names the step, not the transport's message - which can carry
	// a host or a user.
	if body["error"] == nil {
		t.Error("no error was named")
	}

	// And the retry converges on the same account once the writer answers.
	b.BrokerErr = nil
	rec, retry := call(t, h, http.MethodPost, "/v1/tenants/eds/broker-accounts", `{"name":"lightd","publish":["lightstand/+/scene"]}`)
	if rec.Code != http.StatusCreated || retry["status"] != "ready" {
		t.Fatalf("retry: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := b.BrokerAccounts["eds/lightd"]; !ok {
		t.Error("the retry did not reach the writer")
	}
}

func TestBrokerAccountDeleteRevokesIt(t *testing.T) {
	h, _, b := tenantServer(t)
	call(t, h, http.MethodPost, "/v1/tenants", `{"name":"eds"}`)
	call(t, h, http.MethodPost, "/v1/tenants/eds/broker-accounts", `{"name":"lightd","publish":["lightstand/+/scene"]}`)

	rec, _ := call(t, h, http.MethodDelete, "/v1/tenants/eds/broker-accounts/lightd", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if _, ok := b.BrokerAccounts["eds/lightd"]; ok {
		t.Error("the account is still on the broker")
	}
	rec, _ = call(t, h, http.MethodGet, "/v1/tenants/eds/broker-accounts/lightd", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET after delete = %d", rec.Code)
	}
}

// Another tenant's accounts are 404, not 403. These are credentials, and a 403
// would confirm which accounts exist.
func TestAnotherTenantsBrokerAccountsAre404(t *testing.T) {
	h, _, _ := tenantServer(t)
	createTenantFor(t, h, "eds")
	other := createTenantFor(t, h, "tdemo")
	call(t, h, http.MethodPost, "/v1/tenants/eds/broker-accounts", `{"name":"lightd","publish":["lightstand/+/scene"]}`)

	for _, path := range []string{"/v1/tenants/eds/broker-accounts", "/v1/tenants/eds/broker-accounts/lightd"} {
		rec, _ := callAs(t, h, other, http.MethodGet, path, "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s as another tenant = %d, want 404", path, rec.Code)
		}
	}
	rec, _ := callAs(t, h, other, http.MethodDelete, "/v1/tenants/eds/broker-accounts/lightd", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("DELETE as another tenant = %d, want 404", rec.Code)
	}
}

func TestBrokerAccountNeedsAToken(t *testing.T) {
	h, _, _ := tenantServer(t)
	call(t, h, http.MethodPost, "/v1/tenants", `{"name":"eds"}`)

	rec, _ := callAs(t, h, "", http.MethodGet, "/v1/tenants/eds/broker-accounts", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated = %d, want 401", rec.Code)
	}
}
