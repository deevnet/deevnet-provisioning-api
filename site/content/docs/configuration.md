---
title: "Configuration"
weight: 6
---

# Configuration

**The service is configured by environment variables only.** The container has no configuration
file. Values below are illustrative; a site's own come from its automation.

## Core

**Two variables are required, and the service refuses to start without them.**

| Variable | Required | Meaning |
|---|---|---|
| `DEEVNET_API_TOKEN` | yes | the operator bearer token for `/v1` |
| `DATABASE_URL` | yes | PostgreSQL connection string. The schema is migrated on start |
| `DEEVNET_AGENT_TOKEN` | no | the exit node's egress agent. It reads `GET /v1/fabric/egress` and nothing else |
| `DEEVNET_API_LISTEN` | no | listen address, default `:8080` |
| `DEEVNET_API_TLS_CERT`, `DEEVNET_API_TLS_KEY` | no | serve TLS, 1.2 at the least. Set both or neither |

With only these set, the service runs and every tenant route answers `501`.

## Site

**Tenants are served when `DEEVNET_SITE` is set.** Every variable in this table is then required,
and the service refuses to start if any is empty.

| Variable | Example | Meaning |
|---|---|---|
| `DEEVNET_SITE` | `site` | site label in zone names |
| `DEEVNET_SITE_OCTET` | `20` | second octet of the site's address block |
| `DEEVNET_ROOT_DOMAIN` | `example.net` | the domain every site's zones sit under |
| `DEEVNET_VRF_VNI_BASE`, `DEEVNET_VNET_VNI_BASE` | `10000`, `20000` | bases a tenant's VXLAN ids derive from |
| `DEEVNET_FABRIC_CONTROLLER`, `DEEVNET_FABRIC_NODE` | `evpn1`, `hyp002` | the attachment every tenant gets |
| `DEEVNET_DNS_UPDATE_SERVER` | `tdns.site.example.net` | where tenants send RFC 2136 updates |
| `DEEVNET_DNS_APEX_NS` | `ns1.site.example.net` | apex NS and SOA primary of tenant zones |
| `DEEVNET_DNS_UPDATE_FROM` | `10.20.50.0/24` | networks that may attempt an update, comma-separated |
| `DEEVNET_STATE_ENDPOINT`, `DEEVNET_STATE_BUCKET` | `https://tfstate.site.example.net:9000`, `tf-state` | the state store tenants are offered |
| `DEEVNET_RESOLVER_FORWARD_TO` | | the address the site resolver forwards tenant zones to |
| `DEEVNET_WORKLOAD_RESOLVER` | | the resolver a workload is given |
| `POWERDNS_API_URL` | | the tenant DNS server's HTTP API |
| `OPNSENSE_API_URL` | | the core router's API |
| `MINIO_ADMIN_ENDPOINT` | | the state store's admin API |
| `PROXMOX_API_URL` | | the tenant hypervisor's API |
| `DEEVNET_TENANT_VMID_BASE` | `2000` | first VMID of the tenant band |
| `DEEVNET_MAC_NAMESPACE` | `02:de:20` | prefix of the MAC a workload derives from its VMID |
| `DEEVNET_TEMPLATE_PREFIX` | `fedora-server-` | the newest template matching it is cloned |
| `DEEVNET_TENANT_STORAGE`, `DEEVNET_TENANT_DISK` | `local-lvm`, `scsi0` | where a workload lands, and the disk grown |
| `DEEVNET_TENANT_CIUSER` | | the account a workload's keys go to, reported as `login_user` |

## Secret store

**Backend credentials come from OpenBao when `OPENBAO_ADDR` is set**
([ADR-0016](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/substrate/0016-substrate-secrets-openbao/)). They are the fields of one KV secret,
and the same store seals stored tenant secrets and issues enrollment tokens.

| Variable | Default | Meaning |
|---|---|---|
| `OPENBAO_ADDR` | | turns OpenBao on; the next two rows are then required |
| `OPENBAO_CACERT` | | the certificate the listener is verified against |
| `OPENBAO_ROLE_ID`, `OPENBAO_SECRET_ID` | | the service's AppRole |
| `OPENBAO_KV_MOUNT`, `OPENBAO_KV_PATH` | `deevnet-api`, `backends` | where the credentials are |
| `OPENBAO_TRANSIT_KEY` | `tenant-secrets` | the key that seals stored secrets |
| `DEEVNET_ENROLLMENT_TTL` | `72h` | how long an enrollment token lives |

The fields the secret holds:

| Field | For |
|---|---|
| `powerdns_api_key` | the tenant DNS server |
| `opnsense_api_key`, `opnsense_api_secret` | the core router |
| `minio_admin_access_key`, `minio_admin_secret_key` | the state store |
| `proxmox_token_id`, `proxmox_token_secret` | the tenant hypervisor |
| `token_hmac_key` | the MAC key of tenant tokens: base64, at least 32 bytes |
| `omada_client_id`, `omada_client_secret` | the wireless controller; needed only with Wi-Fi keys |
| `broker_writer_key` | the broker account writer; needed only with broker accounts |
| `log_writer_key` | the log store's user writer; needed only with the log store |
| `grafana_admin_password` | the dashboard server; needed only with dashboards |

**Without OpenBao, the same names are read from the environment in upper case.** That is for tests
and local runs: there is then no enrollment and no encryption at rest.

## Backend TLS

**Each backend is verified unless told otherwise.**

| Variable | Default | Meaning |
|---|---|---|
| `OPNSENSE_INSECURE_TLS`, `PROXMOX_INSECURE_TLS` | `false` | `true` only for a device still serving a self-signed certificate |
| `MINIO_ADMIN_TLS` | `false` | `true` when the state store serves TLS |
| `MINIO_ADMIN_CACERT` | | the CA the state store is verified against; required with `MINIO_ADMIN_TLS` |
| `OMADA_INSECURE_TLS` | `false` | `true` only for a wireless controller still serving a self-signed certificate |

## Optional capabilities

**Each device-facing capability is turned on by one variable, and a site may leave any of them
off.** An unset capability is not a degraded state: its routes refuse with a reason, and a site
with no wireless controller or no broker is a legitimate site.

### Wi-Fi keys

| Variable | Meaning |
|---|---|
| `OMADA_API_URL` | the wireless controller's API; turns Wi-Fi keys on |
| `DEEVNET_IOT_TRUST_CLASSES` | the trust classes served, as comma-separated `name=ssid:vlan`, for example `iot=SITE-IOT:30` |
| `DEEVNET_ADMISSION_WIFI_CLASS` | the trust class an admission's Wi-Fi key is issued in; unset, admissions carry none |

### Fixed device addresses

| Variable | Default | Meaning |
|---|---|---|
| `DEEVNET_IOT_ADDRESS_RANGES` | | the part of each trust class's network tenants are given, as comma-separated `name=subnet:first-last`, for example `iot=10.20.30.0/24:10.20.30.25-10.20.30.200`. Each name must be a served trust class |
| `DEEVNET_IOT_ADDRESSES_PER_TENANT` | `16` | one tenant's share of a range |

They need no credential of their own: the reservations go to the router the resolver forwards
already go to.

### Broker accounts

| Variable | Default | Meaning |
|---|---|---|
| `DEEVNET_BROKER_WRITER_ADDR` | | the messaging host's writer, reached over SSH; turns broker accounts on |
| `DEEVNET_BROKER_WRITER_USER` | | the account the writer runs as |
| `DEEVNET_BROKER_HOST_KEY` | | the host's public key, pinned |
| `DEEVNET_BROKER_CONNECT_TIMEOUT`, `DEEVNET_BROKER_SESSION_TIMEOUT` | `10s`, `30s` | reaching the host, and the whole exchange once connected |

### Log store

| Variable | Meaning |
|---|---|
| `DEEVNET_LOG_WRITER_ADDR` | the log store's user writer, reached over SSH; turns log tokens on |
| `DEEVNET_LOG_WRITER_USER`, `DEEVNET_LOG_HOST_KEY` | the account the writer runs as, and the host's pinned public key |
| `DEEVNET_LOG_CONNECT_TIMEOUT`, `DEEVNET_LOG_SESSION_TIMEOUT` | as for the broker's |
| `DEEVNET_LOG_ENDPOINT` | what a tenant is told to send logs to: the store's HTTPS address, which is not where the writer lives |

### Dashboards

| Variable | Default | Meaning |
|---|---|---|
| `DEEVNET_GRAFANA_URL` | | the dashboard server, both where the API reaches it and what a tenant is told; turns dashboards on |
| `DEEVNET_GRAFANA_CACERT` | | the CA the server is verified against |
| `DEEVNET_GRAFANA_ADMIN_USER` | `admin` | the server admin the API acts as |

Dashboards need the log store: `DEEVNET_LOG_ENDPOINT` and `DEEVNET_LOG_WRITER_ADDR` are required
with them, because a tenant's data sources carry its log read token.
