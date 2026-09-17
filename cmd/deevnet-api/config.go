package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/backend/minio"
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
		for _, k := range credentials {
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
		TenantVMIDBase:    ints["DEEVNET_TENANT_VMID_BASE"],
		MACNamespace:      getenv("DEEVNET_MAC_NAMESPACE"),
		TemplatePrefix:    getenv("DEEVNET_TEMPLATE_PREFIX"),
		Storage:           getenv("DEEVNET_TENANT_STORAGE"),
		Disk:              getenv("DEEVNET_TENANT_DISK"),
		CIUser:            getenv("DEEVNET_TENANT_CIUSER"),
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
	return wiring{tenants: svc, sealer: sealer, site: site}, nil
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
