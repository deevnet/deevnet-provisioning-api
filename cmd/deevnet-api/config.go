package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/backend/brokerwriter"
	"github.com/deevnet/deevnet-provisioning-api/internal/backend/grafana"
	"github.com/deevnet/deevnet-provisioning-api/internal/backend/logwriter"
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

// brokerEnv is what the API needs to write MQTT broker accounts (ADR-0012 §3;
// CHG-0016). DEEVNET_BROKER_WRITER_ADDR turns it on; the rest is then
// required. Optional again, and for the same reason as omadaEnv: a site with
// no broker is a legitimate site, and requiring these would fail every such
// deployment on the next image bump.
//
// The host key is here rather than in the credentials because it is a public
// key, and because it is a PIN: it belongs with the address it pins, and
// changing the messaging VM's address without its host key should be awkward.
var brokerEnv = []string{
	"DEEVNET_BROKER_WRITER_ADDR",
	"DEEVNET_BROKER_WRITER_USER",
	"DEEVNET_BROKER_HOST_KEY",
}

// brokerCredentials are checked only when DEEVNET_BROKER_WRITER_ADDR is set.
// The API's own key, used for nothing else, so revoking it revokes exactly the
// capability to write broker accounts.
var brokerCredentials = []string{
	"broker_writer_key",
}

// logEnv is what the API needs to maintain tenants' users in the log store
// (ADR-0027; CHG-0020). DEEVNET_LOG_WRITER_ADDR turns it on; the rest is then
// required. Optional for the same reason as the broker's: a site with no log
// store is a legitimate site, and a tenant there simply has no log tokens.
//
// DEEVNET_LOG_ENDPOINT is what a tenant is TOLD to send logs to, which is not
// the same thing as where the writer lives: the writer is reached over SSH, and
// the endpoint is the store's HTTPS port. A site can have one without the
// other, so the endpoint is not required by this gate.
var logEnv = []string{
	"DEEVNET_LOG_WRITER_ADDR",
	"DEEVNET_LOG_WRITER_USER",
	"DEEVNET_LOG_HOST_KEY",
}

// logCredentials are checked only when DEEVNET_LOG_WRITER_ADDR is set. A
// separate key from the broker's: revoking one must not revoke the other, and
// the two writers are on different hosts with different blast radii.
var logCredentials = []string{
	"log_writer_key",
}

// grafanaEnv is what the API needs to give tenants their dashboards (ADR-0024;
// CHG-0024). DEEVNET_GRAFANA_URL turns it on; the rest is then required.
// Optional for the same reason as the others, and it also needs the log store:
// the data sources carry the tenant's log read token, and point at
// DEEVNET_LOG_ENDPOINT.
//
// The URL is both where the API reaches the server and what a tenant is told,
// because both reach it by the same name. The CA verifies the server, and the
// data sources verify the log store with it: both certificates come from the
// site CA.
var grafanaEnv = []string{
	"DEEVNET_GRAFANA_URL",
	"DEEVNET_GRAFANA_CACERT",
	"DEEVNET_LOG_ENDPOINT",
	"DEEVNET_LOG_WRITER_ADDR",
}

// grafanaCredentials are checked only when DEEVNET_GRAFANA_URL is set. The
// server admin's password: creating an organisation is a server-admin act, and
// no organisation-scoped token can do it.
var grafanaCredentials = []string{
	"grafana_admin_password",
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
//
//	DEEVNET_GRAFANA_ADMIN_USER     "admin"
//	DEEVNET_BROKER_CONNECT_TIMEOUT "10s": reaching the messaging VM
//	DEEVNET_BROKER_SESSION_TIMEOUT "30s": the whole exchange once connected.
//	                               A tenant's terraform apply is holding the
//	                               other end, so neither may be unbounded.

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
		for _, k := range append(append(append(append(append([]string{}, credentials...), omadaCredentials...), brokerCredentials...), logCredentials...), grafanaCredentials...) {
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
		LogEndpoint:       getenv("DEEVNET_LOG_ENDPOINT"),
		DashboardURL:      getenv("DEEVNET_GRAFANA_URL"),
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
	if getenv("DEEVNET_BROKER_WRITER_ADDR") != "" {
		if missing := empty(getenv, brokerEnv); len(missing) > 0 {
			return wiring{}, fmt.Errorf("DEEVNET_BROKER_WRITER_ADDR is set, but these are empty: %s", strings.Join(missing, ", "))
		}
		for _, k := range brokerCredentials {
			if creds[k] == "" {
				return wiring{}, fmt.Errorf("DEEVNET_BROKER_WRITER_ADDR is set, but %s is missing from the backend credentials", k)
			}
		}
	}
	if getenv("DEEVNET_LOG_WRITER_ADDR") != "" {
		if missing := empty(getenv, logEnv); len(missing) > 0 {
			return wiring{}, fmt.Errorf("DEEVNET_LOG_WRITER_ADDR is set, but these are empty: %s", strings.Join(missing, ", "))
		}
		for _, k := range logCredentials {
			if creds[k] == "" {
				return wiring{}, fmt.Errorf("DEEVNET_LOG_WRITER_ADDR is set, but %s is missing from the backend credentials", k)
			}
		}
	}
	if getenv("DEEVNET_GRAFANA_URL") != "" {
		if missing := empty(getenv, grafanaEnv); len(missing) > 0 {
			return wiring{}, fmt.Errorf("DEEVNET_GRAFANA_URL is set, but these are empty: %s", strings.Join(missing, ", "))
		}
		for _, k := range grafanaCredentials {
			if creds[k] == "" {
				return wiring{}, fmt.Errorf("DEEVNET_GRAFANA_URL is set, but %s is missing from the backend credentials", k)
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
	// Same reasoning again: a site with no broker leaves BrokerWriter nil and
	// the broker-account endpoints refuse with a reason.
	//
	// New() parses both keys here, so a bad key or an unparseable pin is a
	// startup failure rather than a failed apply for whichever tenant goes
	// first. There is no insecure fallback to configure: an unpinnable host is
	// a configuration error, not a warning.
	if getenv("DEEVNET_BROKER_WRITER_ADDR") != "" {
		connect, err := durationEnv(getenv, "DEEVNET_BROKER_CONNECT_TIMEOUT", 10*time.Second)
		if err != nil {
			return wiring{}, err
		}
		session, err := durationEnv(getenv, "DEEVNET_BROKER_SESSION_TIMEOUT", 30*time.Second)
		if err != nil {
			return wiring{}, err
		}
		w, err := brokerwriter.New(brokerwriter.Config{
			Addr:           getenv("DEEVNET_BROKER_WRITER_ADDR"),
			User:           getenv("DEEVNET_BROKER_WRITER_USER"),
			PrivateKey:     []byte(creds["broker_writer_key"]),
			HostKey:        getenv("DEEVNET_BROKER_HOST_KEY"),
			ConnectTimeout: connect,
			SessionTimeout: session,
		})
		if err != nil {
			return wiring{}, fmt.Errorf("broker account writer: %w", err)
		}
		svc.BrokerWriter = w
	}

	// The log store's user writer. Same shape as the broker's, on a host on the
	// API's own segment: what crosses here is the tenant's tokens themselves,
	// so the host key is pinned and there is no fallback that would connect
	// without one.
	if getenv("DEEVNET_LOG_WRITER_ADDR") != "" {
		connect, err := durationEnv(getenv, "DEEVNET_LOG_CONNECT_TIMEOUT", 10*time.Second)
		if err != nil {
			return wiring{}, err
		}
		session, err := durationEnv(getenv, "DEEVNET_LOG_SESSION_TIMEOUT", 30*time.Second)
		if err != nil {
			return wiring{}, err
		}
		w, err := logwriter.New(logwriter.Config{
			Addr:           getenv("DEEVNET_LOG_WRITER_ADDR"),
			User:           getenv("DEEVNET_LOG_WRITER_USER"),
			PrivateKey:     []byte(creds["log_writer_key"]),
			HostKey:        getenv("DEEVNET_LOG_HOST_KEY"),
			ConnectTimeout: connect,
			SessionTimeout: session,
		})
		if err != nil {
			return wiring{}, fmt.Errorf("log store user writer: %w", err)
		}
		svc.LogWriter = w
	}

	// The dashboard server. Reached over HTTPS on the API's own segment, and
	// verified: what crosses is the server admin's password and each tenant's
	// read token.
	if getenv("DEEVNET_GRAFANA_URL") != "" {
		d, err := grafana.New(grafana.Config{
			URL:           getenv("DEEVNET_GRAFANA_URL"),
			AdminUser:     orDefault(getenv("DEEVNET_GRAFANA_ADMIN_USER"), "admin"),
			AdminPassword: creds["grafana_admin_password"],
			CAFile:        getenv("DEEVNET_GRAFANA_CACERT"),
			LogEndpoint:   getenv("DEEVNET_LOG_ENDPOINT"),
		})
		if err != nil {
			return wiring{}, fmt.Errorf("dashboard server: %w", err)
		}
		svc.Dashboards = d
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

// durationEnv reads an optional duration. A malformed one is a startup failure
// naming the variable, rather than a silent fall back to the default - a
// timeout that quietly is not what the operator wrote is worse than none.
func durationEnv(getenv func(string) string, key string, def time.Duration) (time.Duration, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", key)
	}
	return d, nil
}

func boolEnv(getenv func(string) string, key string, def bool) bool {
	v, err := strconv.ParseBool(getenv(key))
	if err != nil {
		return def
	}
	return v
}
