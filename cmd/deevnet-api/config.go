package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/backend/minio"
	"github.com/deevnet/deevnet-provisioning-api/internal/backend/omada"
	"github.com/deevnet/deevnet-provisioning-api/internal/backend/opnsense"
	"github.com/deevnet/deevnet-provisioning-api/internal/backend/powerdns"
	"github.com/deevnet/deevnet-provisioning-api/internal/backend/proxmox"
	"github.com/deevnet/deevnet-provisioning-api/internal/openbao"
	"github.com/deevnet/deevnet-provisioning-api/internal/store"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// siteEnv is the site's values. The API serves tenants only when DEEVNET_SITE
// is set, and then refuses to start unless all of these are too: half a
// configuration would build half a tenant.
var siteEnv = []string{
	"DEEVNET_SITE",
	"DEEVNET_SITE_OCTET",
	"DEEVNET_ROOT_DOMAIN",
	"DEEVNET_VRF_VNI_BASE",
	"DEEVNET_VNET_VNI_BASE",
	"DEEVNET_FABRIC_CONTROLLER",
	"DEEVNET_FABRIC_NODE",
	"DEEVNET_DNS_UPDATE_SERVER",
	"DEEVNET_DNS_APEX_NS",
	"DEEVNET_DNS_UPDATE_FROM",
	"DEEVNET_STATE_ENDPOINT",
	"DEEVNET_STATE_BUCKET",
	"DEEVNET_RESOLVER_FORWARD_TO",
	"DEEVNET_WORKLOAD_RESOLVER",
	"POWERDNS_API_URL",
	"OPNSENSE_API_URL",
	"MINIO_ADMIN_ENDPOINT",
	"PROXMOX_API_URL",
	"DEEVNET_TENANT_VMID_BASE",
	"DEEVNET_MAC_NAMESPACE",
	"DEEVNET_TEMPLATE_PREFIX",
	"DEEVNET_TENANT_STORAGE",
	"DEEVNET_TENANT_DISK",
	"DEEVNET_TENANT_CIUSER",
}

// credentials are the backend secrets. With OpenBao (ADR-0016) they are the
// fields of one KV secret; without it, for tests and local runs, they are
// environment variables of the same names in upper case.
var credentials = []string{
	"powerdns_api_key",
	"opnsense_api_key",
	"opnsense_api_secret",
	"minio_admin_access_key",
	"minio_admin_secret_key",
	"proxmox_token_id",
	"proxmox_token_secret",
	// Base64, at least 32 bytes: the MAC key of tenant tokens.
	"token_hmac_key",
}

// omadaEnv is what the API needs to issue tenant Wi-Fi keys (ADR-0012 §3).
// OMADA_API_URL turns it on; the rest is then required. It is deliberately NOT
// part of siteEnv or credentials: a site with no wireless controller is a
// legitimate site - it is what was deployed before CHG-0013 - and putting these
// in the required lists would fail every such deployment on the first image
// bump, before the vault had the values.
var omadaEnv = []string{
	"OMADA_API_URL",
	"DEEVNET_IOT_TRUST_CLASSES",
}

// omadaCredentials are checked only when OMADA_API_URL is set. The API gets its
// OWN Open API client, separate from the one Ansible uses: the permission is
// the same either way, but the blast radius, the rotation and the controller's
// audit log are not.
var omadaCredentials = []string{
	"omada_client_id",
	"omada_client_secret",
}

// openbaoEnv is what the API needs to reach OpenBao. OPENBAO_ADDR turns
// OpenBao on; the rest are then required.
var openbaoEnv = []string{
	"OPENBAO_ADDR",
	"OPENBAO_CACERT",
	"OPENBAO_ROLE_ID",
	"OPENBAO_SECRET_ID",
}

// Optional, with defaults that match the site today:
//
//	OPENBAO_KV_MOUNT       "deevnet-api"
//	OPENBAO_KV_PATH        "backends"
//	OPENBAO_TRANSIT_KEY    "tenant-secrets"
//	DEEVNET_ENROLLMENT_TTL "72h"
//	OPNSENSE_INSECURE_TLS  "true": the router's certificate is self-signed
//	PROXMOX_INSECURE_TLS   "true": so is the node's
//	MINIO_ADMIN_TLS        "false"

// wiring is what main needs beyond the service: the store's sealer and the
// site, which the store uses to derive a workload's identity.
type wiring struct {
	tenants *tenant.Service
	sealer  store.Sealer
	site    tenant.Site
}

// tenantService builds the tenant service, or returns nothing when
// DEEVNET_SITE is unset.
func tenantService(ctx context.Context, getenv func(string) string) (wiring, error) {
	if getenv("DEEVNET_SITE") == "" {
		return wiring{}, nil
	}
	if missing := empty(getenv, siteEnv); len(missing) > 0 {
		return wiring{}, fmt.Errorf("DEEVNET_SITE is set, so tenants are served, but these are empty: %s", strings.Join(missing, ", "))
	}

	var (
		creds    map[string]string
		bao      *openbao.Client
		enroller tenant.Enroller
		sealer   store.Sealer
	)
	if getenv("OPENBAO_ADDR") != "" {
		if missing := empty(getenv, openbaoEnv); len(missing) > 0 {
			return wiring{}, fmt.Errorf("OPENBAO_ADDR is set, but these are empty: %s", strings.Join(missing, ", "))
		}
		var err error
		bao, err = openbao.New(openbao.Config{
			Addr:       getenv("OPENBAO_ADDR"),
			CAFile:     getenv("OPENBAO_CACERT"),
			RoleID:     getenv("OPENBAO_ROLE_ID"),
			SecretID:   getenv("OPENBAO_SECRET_ID"),
			KVMount:    orDefault(getenv("OPENBAO_KV_MOUNT"), "deevnet-api"),
			TransitKey: orDefault(getenv("OPENBAO_TRANSIT_KEY"), "tenant-secrets"),
		})
		if err != nil {
			return wiring{}, err
		}
		kvPath := orDefault(getenv("OPENBAO_KV_PATH"), "backends")
		if creds, err = bao.ReadKV(ctx, kvPath); err != nil {
			return wiring{}, err
		}
		enroller, sealer = bao, bao
	} else {
		creds = map[string]string{}
		// The optional ones are read here too, so a local run without OpenBao
		// can still reach a controller. They are not added to the required
		// check below.
		for _, k := range append(append([]string{}, credentials...), omadaCredentials...) {
			creds[k] = getenv(strings.ToUpper(k))
		}
	}
	var missing []string
	for _, k := range credentials {
		if creds[k] == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		where := "the environment (upper case)"
		if bao != nil {
			where = "the OpenBao KV secret"
		}
		return wiring{}, fmt.Errorf("backend credentials missing from %s: %s", where, strings.Join(missing, ", "))
	}

	ints := map[string]int{}
	for _, k := range []string{"DEEVNET_SITE_OCTET", "DEEVNET_VRF_VNI_BASE", "DEEVNET_VNET_VNI_BASE", "DEEVNET_TENANT_VMID_BASE"} {
		n, err := strconv.Atoi(getenv(k))
		if err != nil {
			return wiring{}, fmt.Errorf("%s: %w", k, err)
		}
		ints[k] = n
	}

	var updateFrom []string
	for _, n := range strings.Split(getenv("DEEVNET_DNS_UPDATE_FROM"), ",") {
		if n = strings.TrimSpace(n); n != "" {
			updateFrom = append(updateFrom, n)
		}
	}

	site := tenant.Site{
		Name:              getenv("DEEVNET_SITE"),
		Octet:             ints["DEEVNET_SITE_OCTET"],
		RootDomain:        getenv("DEEVNET_ROOT_DOMAIN"),
		VRFVNIBase:        ints["DEEVNET_VRF_VNI_BASE"],
		VNetVNIBase:       ints["DEEVNET_VNET_VNI_BASE"],
		ControllerID:      getenv("DEEVNET_FABRIC_CONTROLLER"),
		Node:              getenv("DEEVNET_FABRIC_NODE"),
		DNSUpdateServer:   getenv("DEEVNET_DNS_UPDATE_SERVER"),
		DNSApexNS:         getenv("DEEVNET_DNS_APEX_NS"),
		DNSUpdateFrom:     updateFrom,
		StateEndpoint:     getenv("DEEVNET_STATE_ENDPOINT"),
		StateBucket:       getenv("DEEVNET_STATE_BUCKET"),
		ResolverForwardTo: getenv("DEEVNET_RESOLVER_FORWARD_TO"),
		WorkloadResolver:  getenv("DEEVNET_WORKLOAD_RESOLVER"),
		TenantVMIDBase:    ints["DEEVNET_TENANT_VMID_BASE"],
		MACNamespace:      getenv("DEEVNET_MAC_NAMESPACE"),
		TemplatePrefix:    getenv("DEEVNET_TEMPLATE_PREFIX"),
		Storage:           getenv("DEEVNET_TENANT_STORAGE"),
		Disk:              getenv("DEEVNET_TENANT_DISK"),
		CIUser:            getenv("DEEVNET_TENANT_CIUSER"),
	}
	if getenv("OMADA_API_URL") != "" {
		if missing := empty(getenv, omadaEnv); len(missing) > 0 {
			return wiring{}, fmt.Errorf("OMADA_API_URL is set, but these are empty: %s", strings.Join(missing, ", "))
		}
		var err error
		if site.TrustClasses, err = parseTrustClasses(getenv("DEEVNET_IOT_TRUST_CLASSES")); err != nil {
			return wiring{}, fmt.Errorf("DEEVNET_IOT_TRUST_CLASSES: %w", err)
		}
		for _, k := range omadaCredentials {
			if creds[k] == "" {
				return wiring{}, fmt.Errorf("OMADA_API_URL is set, but %s is missing from the backend credentials", k)
			}
		}
	}
	if err := site.Validate(); err != nil {
		return wiring{}, fmt.Errorf("site: %w", err)
	}

	key, err := base64.StdEncoding.DecodeString(creds["token_hmac_key"])
	if err != nil {
		return wiring{}, fmt.Errorf("token_hmac_key is not base64: %w", err)
	}
	tokens, err := tenant.NewTokens(key)
	if err != nil {
		return wiring{}, err
	}

	ttl := 72 * time.Hour
	if v := getenv("DEEVNET_ENROLLMENT_TTL"); v != "" {
		if ttl, err = time.ParseDuration(v); err != nil {
			return wiring{}, fmt.Errorf("DEEVNET_ENROLLMENT_TTL: %w", err)
		}
	}

	state, err := minio.New(getenv("MINIO_ADMIN_ENDPOINT"), creds["minio_admin_access_key"], creds["minio_admin_secret_key"], boolEnv(getenv, "MINIO_ADMIN_TLS", false))
	if err != nil {
		return wiring{}, fmt.Errorf("MINIO_ADMIN_ENDPOINT: %w", err)
	}

	// One Proxmox client reads the fabric and builds tenant networks and
	// workloads (ADR-0015 §11, §12).
	pve := proxmox.New(getenv("PROXMOX_API_URL"), creds["proxmox_token_id"], creds["proxmox_token_secret"], site, boolEnv(getenv, "PROXMOX_INSECURE_TLS", true))

	svc := &tenant.Service{
		Site:          site,
		DNS:           powerdns.New(getenv("POWERDNS_API_URL"), creds["powerdns_api_key"]),
		Resolver:      opnsense.New(getenv("OPNSENSE_API_URL"), creds["opnsense_api_key"], creds["opnsense_api_secret"], boolEnv(getenv, "OPNSENSE_INSECURE_TLS", true)),
		State:         state,
		Fabric:        pve,
		Network:       pve,
		Compute:       pve,
		Tokens:        tokens,
		EnrollmentTTL: ttl,
	}
	// Assigned only when set: a nil *openbao.Client in the interface would not
	// compare equal to nil.
	if enroller != nil {
		svc.Enroller = enroller
	}
	// Same reasoning: leave Wireless nil at a site with no controller, so the
	// Wi-Fi endpoints refuse with a reason rather than dereferencing nothing.
	if getenv("OMADA_API_URL") != "" {
		svc.Wireless = omada.New(getenv("OMADA_API_URL"),
			creds["omada_client_id"], creds["omada_client_secret"],
			boolEnv(getenv, "OMADA_INSECURE_TLS", true))
	}
	return wiring{tenants: svc, sealer: sealer, site: site}, nil
}

// parseTrustClasses reads "iot=DVNTM-IOT:30,iot_vendor=DVNTM-IOTV:31".
//
// Inventory's deevnet_vlans is still where these are decided (ADR-0009); the
// deployment role projects them here, the way it already does the fabric
// controller. A malformed entry is a startup failure naming that entry, rather
// than a site that quietly serves fewer classes than it was meant to.
func parseTrustClasses(raw string) (map[string]tenant.TrustClass, error) {
	out := map[string]tenant.TrustClass{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, rest, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("%q is not name=ssid:vlan", entry)
		}
		ssid, vlanStr, ok := strings.Cut(rest, ":")
		if !ok {
			return nil, fmt.Errorf("%q is not name=ssid:vlan", entry)
		}
		vlan, err := strconv.Atoi(strings.TrimSpace(vlanStr))
		if err != nil {
			return nil, fmt.Errorf("%q: vlan: %w", entry, err)
		}
		name = strings.TrimSpace(name)
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("trust class %q is declared twice", name)
		}
		out[name] = tenant.TrustClass{Name: name, SSID: strings.TrimSpace(ssid), VLAN: vlan}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no trust classes declared")
	}
	return out, nil
}

func empty(getenv func(string) string, keys []string) []string {
	var missing []string
	for _, k := range keys {
		if getenv(k) == "" {
			missing = append(missing, k)
		}
	}
	return missing
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func boolEnv(getenv func(string) string, key string, def bool) bool {
	v, err := strconv.ParseBool(getenv(key))
	if err != nil {
		return def
	}
	return v
}
