# Release Notes

Every release of the Deevnet API, newest first. Versions are `MAJOR.MINOR.PATCH`; until 1.0 a
minor release may change behavior or configuration, and the notes say so under **Upgrading**.

One tag covers everything this repository builds: the API, the two writers
(`deevnet-broker-account`, `deevnet-log-user`) and `deevnet-kit`.

## Unreleased

### Added

- A documentation site, https://deevnet.github.io/deevnet-provisioning-api/, with the API
  reference rendered from `api/openapi.yaml`.
- `api/openapi.yaml`, an OpenAPI 3.1 specification, as the contract. It replaces
  `docs/api-v1.md`, and tests fail when it and the code disagree on a route or a wire field.

## 0.10.0 (2026-10-06)

### Added

- **Fixed addresses for tenants' devices** (ADR-0035, CHG-0044):
  `POST`, `GET` and `DELETE /v1/tenants/{name}/devices/{device}/address`. The API allocates an
  address from the range a site sets aside, reserves it on the DHCP server for the device's MAC,
  and publishes the device's name in the tenant's zone. A reconcile puts reservations back.
- `deevnet-kit` exports the Pi's certificate authority as `deevnet-kit-ca.pem` (CHG-0031).

### Changed

- **Backend TLS is verified by default.** `PROXMOX_INSECURE_TLS`, `OPNSENSE_INSECURE_TLS` and
  `OMADA_INSECURE_TLS` now default to `false`.

### Upgrading

- **A backend still serving a self-signed certificate must be named.** Set its
  `*_INSECURE_TLS` variable to `true`, or the API fails to reach it.
- **Fixed addresses are off until configured.** Set `DEEVNET_IOT_ADDRESS_RANGES` to turn them on.

## 0.9.1 (2026-09-27)

### Changed

- A workload no longer runs a package upgrade on first boot, so it is reachable sooner and its
  packages are what the template carried.

## 0.9.0 (2026-09-27)

### Added

- **A tenant's `ssh_keys` reach its workloads**, and the workload reports the account they
  landed on as `login_user` (CHG-0028).
- **Admission issues a Wi-Fi key for the tenant developer network** (CHG-0029), in the trust
  class `DEEVNET_ADMISSION_WIFI_CLASS` names. `DELETE /v1/admissions/{name}` revokes the key of
  an admission never used.
- **A Wi-Fi key may bind to one client** with `mac` (CHG-0029).
- The state store's admin client can use TLS, verified against the site's certificate authority:
  `MINIO_ADMIN_TLS` and `MINIO_ADMIN_CACERT` (CHG-0030).
- `deevnet-kit` writes the app's broker login to `kit.env`, and sets the Pi's host name and
  Wi-Fi at first boot.

### Changed

- **Deleting a tenant removes its broker accounts** with it (CHG-0028).

## 0.8.1 (2026-09-24)

### Added

- `deevnet-kit selftest`, and a starter dashboard on the take-home Pi.

## 0.8.0 (2026-09-24)

### Added

- **A dashboard organization per tenant** (ADR-0024, CHG-0024). Creating a tenant creates its
  organization, an Editor login and three log data sources with fixed UIDs, and returns the
  login in `dashboard`. The password is also returned on a reconcile.
- **`deevnet-kit`**, the API's stand-in on a take-home Raspberry Pi.

## 0.7.0 (2026-09-22)

### Changed

- **The `log` topic level is reserved for devices' own logs** (ADR-0027 §3). A device account
  may publish only `log/<its own device>`; a workload account may subscribe under `log/` and
  not publish there.

### Upgrading

- A broker account whose patterns reach into `log/` in a way this forbids is refused the next
  time it is applied.

## 0.6.0 (2026-09-22)

### Added

- **Log store tokens for each tenant** (CHG-0020): an ingest token and a read token, returned in
  `log` on create and on reconcile, with the tenant's partition family in `account_id`.
- `deevnet-log-user`, the writer that maintains the log store's users.

## 0.5.1 (2026-09-20)

### Fixed

- The broker account writer's connection pins the host key's algorithm as well as the key, so
  it no longer fails against a host that offers several.

## 0.5.0 (2026-09-20)

### Added

- **Broker accounts** (CHG-0016): `POST`, `GET` and `DELETE /v1/tenants/{name}/broker-accounts`.
  The API issues a tenant's MQTT accounts, writes the tenant prefix onto every topic pattern,
  and keeps only a hash of the password.
- `deevnet-broker-account`, the writer that puts an account into the broker's database.

## 0.4.0 (2026-09-20)

### Added

- **The device registry**: `POST`, `GET` and `DELETE /v1/tenants/{name}/devices`. An entry is a
  device's identity and grants it nothing.

## 0.3.1 (2026-09-18)

### Fixed

- Revoking a tenant's last Wi-Fi key no longer fails. The wireless controller refuses an empty
  key profile, so the API leaves one unusable placeholder entry in it.

## 0.3.0 (2026-09-18)

### Added

- **Wi-Fi keys**: `POST`, `GET` and `DELETE /v1/tenants/{name}/wifi-keys`. One key per tenant
  per trust class; the API chooses the password and takes the SSID and VLAN from the class.

## 0.2.6 (2026-09-17)

### Changed

- A workload is given a recursive resolver, not the authoritative tenant DNS server.

### Upgrading

- **`DEEVNET_WORKLOAD_RESOLVER` is a new required site variable.**

## 0.2.5 (2026-09-17)

### Added

- `secrets_stored` on a tenant read: whether the API can still read the secrets it holds.

## 0.2.4 (2026-09-17)

### Fixed

- A stored secret that can no longer be opened loses that secret, not the whole tenant: the
  tenant still reads, and supplies the secret again.

## 0.2.3 (2026-09-17)

### Changed

- The audit log names the caller, and changes to published names are audited.

## 0.2.2 (2026-09-17)

### Fixed

- A tenant whose registry row is gone is answered `404`, not `401`, so its provider restores it.

## 0.2.1 (2026-09-17)

### Fixed

- A name published beside a workload no longer takes over the workload's reverse record.

## 0.2.0 (2026-09-17)

### Added

- **Tenants**: create, restore, resume, read, reconcile and delete, with index allocation
  against the registry and the fabric (ADR-0015).
- **Admission and tenant tokens**: `POST /v1/admissions` issues a single-use enrollment token,
  and a tenant's own token verifies without the registry (ADR-0015 §10).
- **Workloads and published names**: `/v1/tenants/{name}/workloads` and `/records`
  (ADR-0015 §11–§13).
- **Secrets from OpenBao**, sealing of stored tenant secrets, and TLS (ADR-0016).
- **An agent token** that reads `GET /v1/fabric/egress` and nothing else (ADR-0015 §7).

## 0.1.0 (2026-09-14)

The first tagged release.

### Added

- The service shell: `/healthz`, `/readyz`, `/version`, and a token-gated `/v1`.
