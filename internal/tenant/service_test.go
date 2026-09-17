package tenant_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

var ctx = context.Background()

func TestCreateAllocatesLowestFreeIndexAndEnsuresEveryBackend(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	st.Put(tenant.Record{Name: "eds", Index: 1, Status: tenant.StatusReady})

	res, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Record.Index != 2 || res.Outcome != tenant.OutcomeCreated || res.Record.Status != tenant.StatusReady {
		t.Fatalf("got index %d outcome %s status %s, want 2 created ready", res.Record.Index, res.Outcome, res.Record.Status)
	}

	dns, ok := b.DNSTenants["tdemo"]
	if !ok {
		t.Fatal("DNS was not ensured")
	}
	wantZones := []string{"tdemo.mobile.deevnet.net", "130.20.10.in-addr.arpa"}
	if strings.Join(dns.Zones, ",") != strings.Join(wantZones, ",") || dns.Secret != res.Issued.TSIGSecret || dns.Algorithm != "hmac-sha256" {
		t.Errorf("DNS tenant = %+v, want zones %v and the issued secret", dns, wantZones)
	}
	for _, z := range wantZones {
		if f, ok := b.Forwards[z]; !ok || f.Server != "10.20.25.21" {
			t.Errorf("forward for %s = %+v, want to 10.20.25.21", z, f)
		}
	}
	if s := b.States["tdemo"]; s.Prefix != "tenants/tdemo/" || s.Bucket != "tf-state" || s.Secret != res.Issued.StateSecret {
		t.Errorf("state tenant = %+v", s)
	}

	if raw, err := base64.StdEncoding.DecodeString(res.Issued.TSIGSecret); err != nil || len(raw) != 32 {
		t.Errorf("TSIG secret is not base64 of 32 bytes")
	}
	if len(res.Issued.StateSecret) != 40 {
		t.Errorf("state secret %d chars, want 40", len(res.Issued.StateSecret))
	}
	if name, ok := svc.Tokens.Verify(res.Issued.APIToken); !ok || name != "tdemo" {
		t.Errorf("issued token does not verify for tdemo")
	}
	rec, _ := st.Get(ctx, "tdemo")
	if string(rec.Secrets.APITokenHash) != string(tenant.HashToken(res.Issued.APIToken)) {
		t.Error("the registry does not hold the token's hash")
	}
	if len(rec.Steps) != 4 {
		t.Errorf("steps recorded = %v, want dns, resolver, state and network", rec.Steps)
	}
	net, ok := b.Networks["tdemo"]
	if !ok || net.VRFVNI != 10002 || net.Subnet != "10.20.130.0/24" || net.VNets[0].ID != "tdemo0" || net.VNets[0].Tag != 20020 {
		t.Errorf("network = %+v", net)
	}
}

func TestAllocationSkipsIndexesTheFabricCarries(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	// Zones left on the fabric after the registry was lost.
	b.FabricClaims = []tenant.Claim{{Index: 1, Zone: "eds"}, {Index: 2, Zone: "other"}}

	res, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Record.Index != 3 {
		t.Fatalf("index = %d, want 3", res.Record.Index)
	}
}

func TestCreateWithoutStateReusesTheIndexItsOwnZoneHolds(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	b.FabricClaims = []tenant.Claim{{Index: 5, Zone: "tdemo"}}

	res, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Record.Index != 5 {
		t.Fatalf("index = %d, want 5, the index the fabric already uses for this tenant", res.Record.Index)
	}
}

var testTokens, _ = tenant.NewTokens(tenanttest.TokenKey)

func restore(name string, index int) tenant.CreateRequest {
	tok, err := testTokens.Issue(name)
	if err != nil {
		panic(err)
	}
	return tenant.CreateRequest{
		Name:        name,
		Index:       index,
		TSIGSecret:  base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		StateSecret: "state-secret-from-tenant-state",
		APIToken:    tok,
	}
}

func TestRestoreKeepsAFreeIndexAndTheSuppliedSecrets(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	req := restore("tdemo", 7)
	// Its own zone is still on the fabric: the same tenant coming back.
	b.FabricClaims = []tenant.Claim{{Index: 7, Zone: "tdemo"}}

	res, err := svc.Create(ctx, req)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Record.Index != 7 || res.Outcome != tenant.OutcomeRestored {
		t.Fatalf("got index %d outcome %s, want 7 restored", res.Record.Index, res.Outcome)
	}
	if b.DNSTenants["tdemo"].Secret != req.TSIGSecret || b.States["tdemo"].Secret != req.StateSecret {
		t.Error("the backends were not given the restored secrets")
	}
	rec, _ := st.Get(ctx, "tdemo")
	if string(rec.Secrets.APITokenHash) != string(tenant.HashToken(req.APIToken)) {
		t.Error("the registry does not hold the restored token's hash")
	}
}

func TestRestoreIsIssuedANewIndexWhenAnotherTenantTookIt(t *testing.T) {
	svc, st, _ := tenanttest.NewService()
	st.Put(tenant.Record{Name: "grooveiq", Index: 7, Status: tenant.StatusReady})

	res, err := svc.Create(ctx, restore("tdemo", 7))
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Record.Index != 1 || res.Outcome != tenant.OutcomeReissued {
		t.Fatalf("got index %d outcome %s, want 1 reissued", res.Record.Index, res.Outcome)
	}
}

func TestRestoreIsReissuedWhenTheFabricHoldsAnotherTenantsZone(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	b.FabricClaims = []tenant.Claim{{Index: 7, Zone: "grooveiq"}}

	res, err := svc.Create(ctx, restore("tdemo", 7))
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Record.Index == 7 || res.Outcome != tenant.OutcomeReissued {
		t.Fatalf("got index %d outcome %s, want a new index, reissued", res.Record.Index, res.Outcome)
	}
}

func TestSecondCreateOfAReadyTenantIsRefused(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"}); !errors.Is(err, tenant.ErrExists) {
		t.Fatalf("err = %v, want ErrExists", err)
	}
}

func TestRestoreOverASurvivingRegistryKeepsTheRegistryIndex(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	first, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"})
	if err != nil {
		t.Fatal(err)
	}

	req := restore("tdemo", 9)
	res, err := svc.Create(ctx, req)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Record.Index != first.Record.Index || res.Outcome != tenant.OutcomeReconciled {
		t.Fatalf("got index %d outcome %s, want %d reconciled", res.Record.Index, res.Outcome, first.Record.Index)
	}
	if b.DNSTenants["tdemo"].Secret != req.TSIGSecret {
		t.Error("supplied secrets must win: the tenant's state is the authoritative copy")
	}
	rec, _ := st.Get(ctx, "tdemo")
	if rec.Secrets.State != req.StateSecret {
		t.Error("the registry kept the old state secret")
	}
}

func TestFailedStepLeavesTheTenantResumable(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	b.FailResolver = errors.New("dial tcp 10.20.25.1:443: connection refused")

	res, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"})
	var stepErr *tenant.StepError
	if !errors.As(err, &stepErr) || stepErr.Step != tenant.StepResolver {
		t.Fatalf("err = %v, want a resolver StepError", err)
	}
	if strings.Contains(err.Error(), "10.20.25.1") {
		t.Errorf("the error message leaks the backend error: %q", err)
	}
	if res.Record.Status != tenant.StatusProvisioning {
		t.Fatalf("status = %s, want provisioning", res.Record.Status)
	}
	if _, ok := b.States["tdemo"]; ok {
		t.Error("the state step ran after the resolver step failed")
	}
	firstIndex := res.Record.Index

	b.FailResolver = nil
	res, err = svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if res.Outcome != tenant.OutcomeResumed || res.Record.Status != tenant.StatusReady || res.Record.Index != firstIndex {
		t.Fatalf("got %s %s index %d, want resumed ready index %d", res.Outcome, res.Record.Status, res.Record.Index, firstIndex)
	}
	// The first response never reached the caller, so its token is replaced.
	rec, _ := st.Get(ctx, "tdemo")
	if res.Issued.APIToken == "" || string(rec.Secrets.APITokenHash) != string(tenant.HashToken(res.Issued.APIToken)) {
		t.Error("a resume must issue a new token and store its hash")
	}
}

func TestDeleteIsRefusedWhileTheTenantHasWorkloads(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateWorkload(ctx, "tdemo", tenant.WorkloadRequest{Name: "web"}); err != nil {
		t.Fatal(err)
	}

	if err := svc.Delete(ctx, "tdemo"); !errors.Is(err, tenant.ErrHasWorkloads) {
		t.Fatalf("err = %v, want ErrHasWorkloads", err)
	}
	if len(b.DNSTenants) != 1 || len(b.Networks) != 1 {
		t.Fatal("something was removed although the delete was refused")
	}

	if err := svc.DeleteWorkload(ctx, "tdemo", "web"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, "tdemo"); err != nil {
		t.Fatalf("delete after the workload went: %v", err)
	}
	if len(b.Networks) != 0 {
		t.Error("the network survived the tenant")
	}
}

func TestWorkloadsDeriveTheirIdentity(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"}); err != nil {
		t.Fatal(err)
	}

	first, err := svc.CreateWorkload(ctx, "eds", tenant.WorkloadRequest{Name: "svc", SSHKeys: []string{"ssh-ed25519 AAAA"}})
	if err != nil {
		t.Fatalf("create workload: %v", err)
	}
	// index 1, ordinal 0: VMID 2000 + 1*40 + 0, .10, and the MAC from the VMID.
	if first.Ordinal != 0 || first.VMID != 2040 || first.Address != "10.20.129.10" || first.MAC != "02:de:20:00:07:f8" {
		t.Fatalf("workload = %+v", first)
	}
	if first.Status != tenant.StatusReady || first.Cores != 2 || first.MemoryMB != 2048 {
		t.Fatalf("workload = %+v, want ready with the default sizing", first)
	}
	spec := b.Workloads[first.VMID]
	if spec.Name != "eds-svc" || spec.Bridge != "eds0" || spec.Address != "10.20.129.10/24" || spec.Gateway != "10.20.129.1" {
		t.Fatalf("spec = %+v", spec)
	}
	if spec.TemplatePrefix != "fedora-server-" || spec.CIUser != "a_autoprov" || spec.SSHKeys[0] != "ssh-ed25519 AAAA" {
		t.Fatalf("spec = %+v", spec)
	}
	if r, ok := b.DNSRecords["svc.eds.mobile.deevnet.net"]; !ok || r.Address != "10.20.129.10" {
		t.Fatalf("workload name not published: %v", b.DNSRecords)
	}

	second, err := svc.CreateWorkload(ctx, "eds", tenant.WorkloadRequest{Name: "other", Cores: 4, MemoryMB: 4096, DiskGB: 40})
	if err != nil {
		t.Fatal(err)
	}
	if second.Ordinal != 1 || second.VMID != 2041 || second.Address != "10.20.129.11" {
		t.Fatalf("second workload = %+v", second)
	}
	if spec := b.Workloads[second.VMID]; spec.Cores != 4 || spec.MemoryMB != 4096 || spec.DiskGB != 40 || spec.Disk != "scsi0" {
		t.Fatalf("second spec = %+v", spec)
	}

	// Re-applying keeps identity and takes the new sizing.
	again, err := svc.CreateWorkload(ctx, "eds", tenant.WorkloadRequest{Name: "svc", Cores: 8})
	if err != nil {
		t.Fatal(err)
	}
	if again.VMID != first.VMID || again.Address != first.Address || again.Cores != 8 {
		t.Fatalf("re-applied = %+v", again)
	}

	if err := svc.DeleteWorkload(ctx, "eds", "svc"); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Workloads[first.VMID]; ok {
		t.Error("the VM survived")
	}
	if _, ok := b.DNSRecords["svc.eds.mobile.deevnet.net"]; ok {
		t.Error("the published name survived")
	}
	// The freed ordinal is reused, so addressing stays dense.
	third, err := svc.CreateWorkload(ctx, "eds", tenant.WorkloadRequest{Name: "third"})
	if err != nil || third.Ordinal != 0 {
		t.Fatalf("third = %+v %v, want the freed ordinal", third, err)
	}
}

func TestWorkloadValidation(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	if _, err := svc.CreateWorkload(ctx, "nobody", tenant.WorkloadRequest{Name: "web"}); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("unknown tenant: %v", err)
	}
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"}); err != nil {
		t.Fatal(err)
	}
	var inv *tenant.InvalidError
	for _, name := range []string{"", "UPPER", "-lead", "trail-", strings.Repeat("x", 21)} {
		if _, err := svc.CreateWorkload(ctx, "eds", tenant.WorkloadRequest{Name: name}); !errors.As(err, &inv) {
			t.Errorf("name %q: %v, want InvalidError", name, err)
		}
	}
}

func TestExtraRecords(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.PutRecord(ctx, "eds", "lightd", "10.20.129.10"); err != nil {
		t.Fatal(err)
	}
	if r, ok := b.DNSRecords["lightd.eds.mobile.deevnet.net"]; !ok || r.Address != "10.20.129.10" {
		t.Fatalf("records = %v", b.DNSRecords)
	}
	var inv *tenant.InvalidError
	if err := svc.PutRecord(ctx, "eds", "elsewhere", "10.20.130.10"); !errors.As(err, &inv) {
		t.Errorf("an address outside the tenant subnet: %v, want InvalidError", err)
	}
	if err := svc.PutRecord(ctx, "eds", "bad name", "10.20.129.11"); !errors.As(err, &inv) {
		t.Errorf("an invalid name: %v", err)
	}
	recs, err := svc.ListRecords(ctx, "eds")
	if err != nil || len(recs) != 1 {
		t.Fatalf("list = %v %v", recs, err)
	}
	if err := svc.DeleteRecord(ctx, "eds", "lightd"); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.DNSRecords["lightd.eds.mobile.deevnet.net"]; ok {
		t.Error("the name survived")
	}
	if err := svc.DeleteRecord(ctx, "eds", "lightd"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

func TestDeleteRemovesEverything(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, "tdemo"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(b.DNSTenants)+len(b.Forwards)+len(b.States) != 0 {
		t.Errorf("left behind: dns %v forwards %v state %v", b.DNSTenants, b.Forwards, b.States)
	}
	if _, err := st.Get(ctx, "tdemo"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("registry row survived: %v", err)
	}
	if err := svc.Delete(ctx, "tdemo"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("second delete: %v, want ErrNotFound", err)
	}
}

func TestIndexExhaustion(t *testing.T) {
	svc, st, _ := tenanttest.NewService()
	for n := tenant.MinIndex; n <= tenant.MaxAllocatable; n++ {
		st.Put(tenant.Record{Name: fmt.Sprintf("t%d", n), Index: n})
	}
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "late"}); !errors.Is(err, tenant.ErrExhausted) {
		t.Fatalf("err = %v, want ErrExhausted; index 63 is reserved and never allocated", err)
	}
}

func TestCreateValidation(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	half := restore("tdemo", 3)
	half.APIToken = ""
	for name, req := range map[string]tenant.CreateRequest{
		"name too long":      {Name: "toolongname"},
		"name upper":         {Name: "TDemo"},
		"reserved index":     {Name: "tdemo", Index: 63},
		"half a restore":     half,
		"short state secret": func() tenant.CreateRequest { r := restore("tdemo", 3); r.StateSecret = "short"; return r }(),
	} {
		var inv *tenant.InvalidError
		if _, err := svc.Create(ctx, req); !errors.As(err, &inv) {
			t.Errorf("%s: err = %v, want InvalidError", name, err)
		}
	}
}

func TestEgressListsReadyTenantsOnly(t *testing.T) {
	svc, st, _ := tenanttest.NewService()
	st.Put(tenant.Record{Name: "eds", Index: 1, Status: tenant.StatusReady})
	st.Put(tenant.Record{Name: "half", Index: 2, Status: tenant.StatusProvisioning})

	got, err := svc.Egress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].VRF != "vrf_eds" {
		t.Fatalf("egress = %v, want only vrf_eds", got)
	}
}

func TestNumbering(t *testing.T) {
	site := tenanttest.MobileSite()
	n := site.Numbering(1)
	want := tenant.Numbering{Index: 1, VRFVNI: 10001, VNetVNIBase: 20010, Subnet: "10.20.129.0/24", Gateway: "10.20.129.1", ReverseZone: "129.20.10.in-addr.arpa"}
	if n != want {
		t.Fatalf("numbering(1) = %+v, want %+v", n, want)
	}
	if site.IndexForVRFVNI(10001) != 1 || site.IndexForVRFVNI(9999) != 0 || site.IndexForVRFVNI(10064) != 0 {
		t.Error("IndexForVRFVNI")
	}
	if site.IndexForVNetTag(20010) != 1 || site.IndexForVNetTag(20019) != 1 || site.IndexForVNetTag(20020) != 2 || site.IndexForVNetTag(20005) != 0 {
		t.Error("IndexForVNetTag")
	}
}

func TestTokens(t *testing.T) {
	tok, err := testTokens.Issue("tdemo")
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := testTokens.Verify(tok); !ok || name != "tdemo" {
		t.Fatalf("verify = %q %v", name, ok)
	}
	other, _ := tenant.NewTokens([]byte("another-key-another-key-another-key!!"))
	parts := strings.Split(tok, ".")
	for label, bad := range map[string]string{
		"other key":      func() string { x, _ := other.Issue("tdemo"); return x }(),
		"renamed":        strings.Join([]string{parts[0], "eds", parts[2], parts[3]}, "."),
		"nonce changed":  strings.Join([]string{parts[0], parts[1], parts[2] + "x", parts[3]}, "."),
		"not a token":    "s3cret",
		"bad name":       "dvt1.TOOLONGNAME.abc.def",
		"missing a part": strings.Join(parts[:3], "."),
	} {
		if _, ok := testTokens.Verify(bad); ok {
			t.Errorf("%s: verified", label)
		}
	}
	if _, err := tenant.NewTokens([]byte("short")); err == nil {
		t.Error("a short key was accepted")
	}
}

func TestRestoreRefusesATokenIssuedForAnotherTenant(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	req := restore("tdemo", 3)
	req.APIToken = restore("eds", 3).APIToken
	var inv *tenant.InvalidError
	if _, err := svc.Create(ctx, req); !errors.As(err, &inv) {
		t.Fatalf("err = %v, want InvalidError", err)
	}
}

func TestAdmissionIsSingleUseAndNamed(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	adm, err := svc.Admit(ctx, "tdemo")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Redeem(ctx, adm.EnrollmentToken, "eds"); !errors.Is(err, tenant.ErrNotRedeemable) {
		t.Fatalf("redeem for another name: %v, want ErrNotRedeemable", err)
	}
	// Presenting it for the wrong name spent it.
	if err := svc.Redeem(ctx, adm.EnrollmentToken, "tdemo"); !errors.Is(err, tenant.ErrNotRedeemable) {
		t.Fatalf("redeem after a mismatch: %v, want ErrNotRedeemable", err)
	}

	adm, _ = svc.Admit(ctx, "tdemo")
	if err := svc.Redeem(ctx, adm.EnrollmentToken, "tdemo"); err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if err := svc.Redeem(ctx, adm.EnrollmentToken, "tdemo"); !errors.Is(err, tenant.ErrNotRedeemable) {
		t.Fatalf("second redeem: %v, want ErrNotRedeemable", err)
	}

	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Admit(ctx, "tdemo"); !errors.Is(err, tenant.ErrExists) {
		t.Fatalf("admitting a registered name: %v, want ErrExists", err)
	}

	svc.Enroller = nil
	if _, err := svc.Admit(ctx, "grooveiq"); !errors.Is(err, tenant.ErrNoEnrollment) {
		t.Fatalf("admit without an enroller: %v", err)
	}
}

func TestAuthenticate(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	res, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"})
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := svc.Authenticate(ctx, res.Issued.APIToken); !ok || c.Tenant != "tdemo" || !c.Registered {
		t.Fatalf("current token: %+v %v", c, ok)
	}

	// Another token the API issued for tdemo, but not the one the registry
	// holds: revoked.
	stale, _ := testTokens.Issue("tdemo")
	if _, ok := svc.Authenticate(ctx, stale); ok {
		t.Error("a token the registry does not hold was accepted for a registered tenant")
	}

	// The registry does not know eds: its genuine token authenticates as an
	// unregistered caller, which may only restore itself.
	edsTok, _ := testTokens.Issue("eds")
	if c, ok := svc.Authenticate(ctx, edsTok); !ok || c.Tenant != "eds" || c.Registered {
		t.Fatalf("unregistered tenant: %+v %v", c, ok)
	}
	if _, ok := svc.Authenticate(ctx, "dvt1.eds.forged.mac"); ok {
		t.Error("a forged token authenticated")
	}
}
