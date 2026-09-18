package main

import (
	"context"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func fullEnv() map[string]string {
	return map[string]string{
		"DEEVNET_SITE":                "mobile",
		"DEEVNET_SITE_OCTET":          "20",
		"DEEVNET_ROOT_DOMAIN":         "deevnet.net",
		"DEEVNET_VRF_VNI_BASE":        "10000",
		"DEEVNET_VNET_VNI_BASE":       "20000",
		"DEEVNET_FABRIC_CONTROLLER":   "evpn1",
		"DEEVNET_FABRIC_NODE":         "dv02hyp002p02",
		"DEEVNET_DNS_UPDATE_SERVER":   "tdns.mobile.deevnet.net",
		"DEEVNET_DNS_APEX_NS":         "dv02idn001v01.mobile.deevnet.net",
		"DEEVNET_DNS_UPDATE_FROM":     "10.20.99.0/24, 10.20.10.0/24,10.20.50.0/24",
		"DEEVNET_STATE_ENDPOINT":      "http://tfstate.mobile.deevnet.net:9000",
		"DEEVNET_STATE_BUCKET":        "tf-state",
		"DEEVNET_RESOLVER_FORWARD_TO": "10.20.25.21",
		"DEEVNET_WORKLOAD_RESOLVER":   "10.20.50.1",
		"POWERDNS_API_URL":            "http://10.20.25.21:8081",
		"POWERDNS_API_KEY":            "k",
		"OPNSENSE_API_URL":            "https://10.20.25.1/api",
		"OPNSENSE_API_KEY":            "k",
		"OPNSENSE_API_SECRET":         "s",
		"MINIO_ADMIN_ENDPOINT":        "10.20.25.20:9000",
		"MINIO_ADMIN_ACCESS_KEY":      "deevnet-api",
		"MINIO_ADMIN_SECRET_KEY":      "s",
		"PROXMOX_API_URL":             "https://10.20.99.22:8006",
		"PROXMOX_TOKEN_ID":            "deevnet-api@pve!tenants",
		"PROXMOX_TOKEN_SECRET":        "s",
		"TOKEN_HMAC_KEY":              "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		"DEEVNET_TENANT_VMID_BASE":    "2000",
		"DEEVNET_MAC_NAMESPACE":       "02:de:20",
		"DEEVNET_TEMPLATE_PREFIX":     "fedora-server-",
		"DEEVNET_TENANT_STORAGE":      "local-lvm",
		"DEEVNET_TENANT_DISK":         "scsi0",
		"DEEVNET_TENANT_CIUSER":       "a_autoprov",
	}
}

func TestNoSiteMeansNoTenants(t *testing.T) {
	w, err := tenantService(context.Background(), env(map[string]string{}))
	if w.tenants != nil || err != nil {
		t.Fatalf("got %v %v, want nothing", w.tenants, err)
	}
}

func TestFullEnvBuildsTheService(t *testing.T) {
	w, err := tenantService(context.Background(), env(fullEnv()))
	if err != nil {
		t.Fatal(err)
	}
	svc := w.tenants
	if svc.Enroller != nil || w.sealer != nil {
		t.Error("without OpenBao there is no enrollment and no sealing")
	}
	if got := strings.Join(svc.Site.DNSUpdateFrom, "|"); got != "10.20.99.0/24|10.20.10.0/24|10.20.50.0/24" {
		t.Errorf("update-from = %s", got)
	}
	if svc.DNS == nil || svc.Resolver == nil || svc.State == nil || svc.Fabric == nil || svc.Network == nil || svc.Compute == nil {
		t.Error("a backend is missing")
	}
	if svc.Site.WorkloadVMID(1, 0) != 2040 || svc.Site.MAC(2040) != "02:de:20:00:07:f8" {
		t.Errorf("workload numbering: vmid %d mac %s", svc.Site.WorkloadVMID(1, 0), svc.Site.MAC(2040))
	}
}

func TestHalfConfiguredIsRefusedAndNamesWhatIsMissing(t *testing.T) {
	e := fullEnv()
	delete(e, "OPNSENSE_API_SECRET")
	delete(e, "PROXMOX_TOKEN_ID")
	_, err := tenantService(context.Background(), env(e))
	if err == nil || !strings.Contains(err.Error(), "opnsense_api_secret") || !strings.Contains(err.Error(), "proxmox_token_id") {
		t.Fatalf("err = %v, want both missing names", err)
	}
	if strings.Contains(err.Error(), "=s") {
		t.Error("the error must name variables, not print values")
	}
}

func TestSiteValuesMissing(t *testing.T) {
	e := fullEnv()
	delete(e, "DEEVNET_FABRIC_NODE")
	if _, err := tenantService(context.Background(), env(e)); err == nil || !strings.Contains(err.Error(), "DEEVNET_FABRIC_NODE") {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenBaoHalfConfigured(t *testing.T) {
	e := fullEnv()
	e["OPENBAO_ADDR"] = "https://10.20.25.21:8200"
	_, err := tenantService(context.Background(), env(e))
	if err == nil || !strings.Contains(err.Error(), "OPENBAO_ROLE_ID") {
		t.Fatalf("err = %v, want the missing OpenBao settings named", err)
	}
}

// The deployed API has no wireless controller until CHG-0013 ships its
// credential. If OMADA_API_URL being absent were a startup failure, bumping the
// image would take the running API down before the vault had the values - so
// this is the test that says it does not.
func TestNoOmadaStillStarts(t *testing.T) {
	w, err := tenantService(context.Background(), env(fullEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if w.tenants.Wireless != nil {
		t.Error("no OMADA_API_URL should mean no wireless backend")
	}
	if len(w.tenants.Site.TrustClasses) != 0 {
		t.Error("no trust classes should be served")
	}
}

func TestOmadaWiredWhenConfigured(t *testing.T) {
	e := fullEnv()
	e["OMADA_API_URL"] = "https://10.20.99.40:8043"
	e["DEEVNET_IOT_TRUST_CLASSES"] = "iot=DVNTM-IOT:30"
	e["OMADA_CLIENT_ID"] = "id"
	e["OMADA_CLIENT_SECRET"] = "secret"
	w, err := tenantService(context.Background(), env(e))
	if err != nil {
		t.Fatal(err)
	}
	if w.tenants.Wireless == nil {
		t.Fatal("wireless backend not wired")
	}
	tc, ok := w.tenants.Site.TrustClass("iot")
	if !ok || tc.SSID != "DVNTM-IOT" || tc.VLAN != 30 {
		t.Errorf("trust class = %+v, %v", tc, ok)
	}
}

func TestOmadaHalfConfigured(t *testing.T) {
	for _, tc := range []struct {
		name, drop, want string
	}{
		{"no trust classes", "DEEVNET_IOT_TRUST_CLASSES", "DEEVNET_IOT_TRUST_CLASSES"},
		{"no client id", "OMADA_CLIENT_ID", "omada_client_id"},
		{"no client secret", "OMADA_CLIENT_SECRET", "omada_client_secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fullEnv()
			e["OMADA_API_URL"] = "https://10.20.99.40:8043"
			e["DEEVNET_IOT_TRUST_CLASSES"] = "iot=DVNTM-IOT:30"
			e["OMADA_CLIENT_ID"] = "id"
			e["OMADA_CLIENT_SECRET"] = "secret"
			delete(e, tc.drop)
			_, err := tenantService(context.Background(), env(e))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to name %s", err, tc.want)
			}
			if strings.Contains(err.Error(), "secret\"") {
				t.Error("the error must name variables, not print values")
			}
		})
	}
}

func TestParseTrustClasses(t *testing.T) {
	ok, err := parseTrustClasses("iot=DVNTM-IOT:30, iot_vendor=DVNTM-IOTV:31")
	if err != nil {
		t.Fatal(err)
	}
	if len(ok) != 2 || ok["iot"].VLAN != 30 || ok["iot_vendor"].SSID != "DVNTM-IOTV" {
		t.Fatalf("parsed = %+v", ok)
	}
	for _, bad := range []string{"", "iot", "iot=DVNTM-IOT", "iot=DVNTM-IOT:notanumber", "iot=A:30,iot=B:31"} {
		if _, err := parseTrustClasses(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// A VLAN outside 1-4094 cannot be bound to a key, so it is refused at startup
// rather than at the first tenant's apply.
func TestTrustClassVLANValidated(t *testing.T) {
	e := fullEnv()
	e["OMADA_API_URL"] = "https://10.20.99.40:8043"
	e["DEEVNET_IOT_TRUST_CLASSES"] = "iot=DVNTM-IOT:9999"
	e["OMADA_CLIENT_ID"] = "id"
	e["OMADA_CLIENT_SECRET"] = "secret"
	if _, err := tenantService(context.Background(), env(e)); err == nil || !strings.Contains(err.Error(), "9999") {
		t.Fatalf("err = %v", err)
	}
}
