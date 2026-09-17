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
	if svc.DNS == nil || svc.Resolver == nil || svc.State == nil || svc.Fabric == nil {
		t.Error("a backend is missing")
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
