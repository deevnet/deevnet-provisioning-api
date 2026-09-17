package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/deevnet/deevnet-provisioning-api/internal/backend/minio"
	"github.com/deevnet/deevnet-provisioning-api/internal/backend/opnsense"
	"github.com/deevnet/deevnet-provisioning-api/internal/backend/powerdns"
	"github.com/deevnet/deevnet-provisioning-api/internal/backend/proxmox"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// tenantEnv is every variable the tenant slice reads. The API serves tenants
// only when DEEVNET_SITE is set, and then refuses to start unless all the rest
// are too: half a backend configuration would create half a tenant.
var tenantEnv = []string{
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
	"POWERDNS_API_KEY",
	"OPNSENSE_API_URL",
	"OPNSENSE_API_KEY",
	"OPNSENSE_API_SECRET",
	"MINIO_ADMIN_ENDPOINT",
	"MINIO_ADMIN_ACCESS_KEY",
	"MINIO_ADMIN_SECRET_KEY",
	"PROXMOX_API_URL",
	"PROXMOX_TOKEN_ID",
	"PROXMOX_TOKEN_SECRET",
}

// Optional, with defaults that match the site today:
//
//	OPNSENSE_INSECURE_TLS  "true": the router's certificate is self-signed
//	PROXMOX_INSECURE_TLS   "true": so is the node's
//	MINIO_ADMIN_TLS        "false": the state store is plain HTTP on Platform

// tenantService builds the tenant service from the environment, or returns nil
// when DEEVNET_SITE is unset.
func tenantService(getenv func(string) string) (*tenant.Service, error) {
	if getenv("DEEVNET_SITE") == "" {
		return nil, nil
	}
	var missing []string
	for _, k := range tenantEnv {
		if getenv(k) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("DEEVNET_SITE is set, so tenants are served, but these are empty: %s", strings.Join(missing, ", "))
	}

	ints := map[string]int{}
	for _, k := range []string{"DEEVNET_SITE_OCTET", "DEEVNET_VRF_VNI_BASE", "DEEVNET_VNET_VNI_BASE"} {
		n, err := strconv.Atoi(getenv(k))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
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
	}
	if err := site.Validate(); err != nil {
		return nil, fmt.Errorf("site: %w", err)
	}

	state, err := minio.New(getenv("MINIO_ADMIN_ENDPOINT"), getenv("MINIO_ADMIN_ACCESS_KEY"), getenv("MINIO_ADMIN_SECRET_KEY"), boolEnv(getenv, "MINIO_ADMIN_TLS", false))
	if err != nil {
		return nil, fmt.Errorf("MINIO_ADMIN_ENDPOINT: %w", err)
	}

	return &tenant.Service{
		Site:     site,
		DNS:      powerdns.New(getenv("POWERDNS_API_URL"), getenv("POWERDNS_API_KEY")),
		Resolver: opnsense.New(getenv("OPNSENSE_API_URL"), getenv("OPNSENSE_API_KEY"), getenv("OPNSENSE_API_SECRET"), boolEnv(getenv, "OPNSENSE_INSECURE_TLS", true)),
		State:    state,
		Fabric:   proxmox.New(getenv("PROXMOX_API_URL"), getenv("PROXMOX_TOKEN_ID"), getenv("PROXMOX_TOKEN_SECRET"), site, boolEnv(getenv, "PROXMOX_INSECURE_TLS", true)),
	}, nil
}

func boolEnv(getenv func(string) string, key string, def bool) bool {
	v, err := strconv.ParseBool(getenv(key))
	if err != nil {
		return def
	}
	return v
}
