package tenant_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

func acct() tenant.BrokerAccountRequest {
	return tenant.BrokerAccountRequest{
		Name:      "lightd",
		Publish:   []string{"lightstand/+/scene"},
		Subscribe: []string{"lightstand/+/status"},
	}
}

// The tenant declares patterns relative to its own prefix and never writes its
// own name; the API puts it there (ADR-0012 §10).
func TestPatternsAreStoredPrefixed(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")

	a, err := svc.CreateBrokerAccount(context.Background(), "eds", acct())
	if err != nil {
		t.Fatal(err)
	}
	if a.Publish[0] != "eds/lightstand/+/scene" || a.Subscribe[0] != "eds/lightstand/+/status" {
		t.Errorf("patterns = %v / %v", a.Publish, a.Subscribe)
	}
	if a.Username != "eds-lightd" {
		t.Errorf("username = %q", a.Username)
	}
	// What actually reached the writer must carry the prefix too.
	sent, ok := b.BrokerAccounts["eds/lightd"]
	if !ok {
		t.Fatal("the account never reached the writer")
	}
	if !strings.HasPrefix(sent.Publish[0], "eds/") {
		t.Errorf("the writer was sent an unprefixed pattern: %v", sent.Publish)
	}
}

// The API holds the hash and never the plaintext, so a password comes back
// exactly once.
func TestPasswordIsReturnedOnceAndOnlyTheHashIsKept(t *testing.T) {
	svc, st, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()

	first, err := svc.CreateBrokerAccount(ctx, "eds", acct())
	if err != nil {
		t.Fatal(err)
	}
	if first.Password == "" {
		t.Fatal("no password was returned when the account was minted")
	}
	if first.PasswordHash == first.Password {
		t.Fatal("the stored value is the plaintext, not a hash")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(first.PasswordHash), []byte(first.Password)); err != nil {
		t.Errorf("the stored hash does not verify the returned password: %v", err)
	}

	stored, err := st.GetBrokerAccount(ctx, "eds", "lightd")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored.PasswordHash, first.Password) {
		t.Error("the plaintext is recoverable from what was stored")
	}

	// A re-apply reuses the hash and has nothing to return.
	second, err := svc.CreateBrokerAccount(ctx, "eds", acct())
	if err != nil {
		t.Fatal(err)
	}
	if second.Password != "" {
		t.Error("a re-apply returned a password; the API does not hold one")
	}
	if second.PasswordHash != first.PasswordHash {
		t.Error("a re-apply rotated the password, stranding anything using the old one")
	}
}

// The restore path: the tenant holds the authoritative copy and puts it back.
func TestSuppliedPasswordIsAdopted(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	req := acct()
	req.Password = "the-one-the-devices-have"

	a, err := svc.CreateBrokerAccount(context.Background(), "eds", req)
	if err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(req.Password)); err != nil {
		t.Errorf("the supplied password was not adopted: %v", err)
	}
}

// The property the whole ordering exists for: after a writer failure the hash
// is already durable, so a retry sends the same one.
func TestAWriterFailureLeavesTheHashDurable(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	b.BrokerErr = errors.New("connection lost")

	issued, err := svc.CreateBrokerAccount(ctx, "eds", acct())
	var step *tenant.StepError
	if !errors.As(err, &step) {
		t.Fatalf("err = %v, want a StepError", err)
	}
	if issued.Password == "" {
		t.Error("the password was not returned with the partial account; a retry could not resupply it")
	}
	stored, err := st.GetBrokerAccount(ctx, "eds", "lightd")
	if err != nil {
		t.Fatalf("the row was not written before the writer was called: %v", err)
	}

	// The retry succeeds and must not rotate anything.
	b.BrokerErr = nil
	again, err := svc.CreateBrokerAccount(ctx, "eds", acct())
	if err != nil {
		t.Fatal(err)
	}
	if again.PasswordHash != stored.PasswordHash {
		t.Error("the retry minted a new password, which would strand every device already flashed")
	}
	if again.Status != tenant.StatusReady {
		t.Errorf("status after a successful retry = %s", again.Status)
	}
}

func TestDeviceMustBeRegisteredAndIot(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()

	req := acct()
	req.Device = "nosuch"
	if _, err := svc.CreateBrokerAccount(ctx, "eds", req); err == nil {
		t.Error("an account was issued for a device that is not registered")
	}

	if _, err := svc.CreateDevice(ctx, "eds", tenant.DeviceRequest{Name: "stand-1", TrustClass: "iot"}); err != nil {
		t.Fatal(err)
	}
	req.Device = "stand-1"
	if _, err := svc.CreateBrokerAccount(ctx, "eds", req); err != nil {
		t.Errorf("an iot device was refused an account: %v", err)
	}
}

// A workload account has no device, and that is legitimate: a workload reaches
// the broker over tenant_transit -> iot_backend.
func TestAWorkloadAccountNeedsNoDevice(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	if _, err := svc.CreateBrokerAccount(context.Background(), "eds", acct()); err != nil {
		t.Fatalf("a workload account was refused: %v", err)
	}
}

func TestPatternsAreValidated(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()

	for _, bad := range [][]string{{"/absolute"}, {"$SYS/#"}, {"%u/x"}, {""}, {"a/#/b"}} {
		req := acct()
		req.Publish = bad
		var inv *tenant.InvalidError
		if _, err := svc.CreateBrokerAccount(ctx, "eds", req); !errors.As(err, &inv) {
			t.Errorf("publish %v gave err = %v, want InvalidError", bad, err)
		}
	}
}

// One direction may be empty - a sensor only publishes - but an account that
// grants neither is refused here rather than at the writer, so it reads as a
// bad request and not as the broker being down.
func TestAnAccountMayGrantOneDirectionButNotNeither(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()

	req := acct()
	req.Subscribe = nil
	if _, err := svc.CreateBrokerAccount(ctx, "eds", req); err != nil {
		t.Fatalf("a publish-only account was refused: %v", err)
	}
	if got := b.BrokerAccounts["eds/"+req.Name].Subscribe; len(got) != 0 {
		t.Errorf("the writer was handed subscribe = %v for a publish-only account", got)
	}

	req = acct()
	req.Publish, req.Subscribe = nil, nil
	var inv *tenant.InvalidError
	if _, err := svc.CreateBrokerAccount(ctx, "eds", req); !errors.As(err, &inv) {
		t.Errorf("an account granting nothing gave err = %v, want InvalidError", err)
	}
}

func TestDeleteRemovesFromTheBrokerAndTheRegistry(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	if _, err := svc.CreateBrokerAccount(ctx, "eds", acct()); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteBrokerAccount(ctx, "eds", "lightd"); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.BrokerAccounts["eds/lightd"]; ok {
		t.Error("the account is still in the broker")
	}
	if _, err := st.GetBrokerAccount(ctx, "eds", "lightd"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("the registry row survived: %v", err)
	}
	if err := svc.DeleteBrokerAccount(ctx, "eds", "lightd"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("a second delete: %v, want ErrNotFound", err)
	}
}

// A site with no broker is a legitimate site - every site was one before
// CHG-0015 - and must refuse with a reason rather than panic.
func TestASiteWithNoBrokerRefusesWithAReason(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	svc.BrokerWriter = nil
	ready(t, svc, "eds")
	var inv *tenant.InvalidError
	if _, err := svc.CreateBrokerAccount(context.Background(), "eds", acct()); !errors.As(err, &inv) {
		t.Fatalf("err = %v, want InvalidError", err)
	}
}
