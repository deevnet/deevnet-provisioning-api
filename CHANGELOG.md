# Release Notes

Every release of the Deevnet API, newest first. Versions are `MAJOR.MINOR.PATCH`; until 1.0 a
minor release may change behavior or configuration, and the notes say so under **Upgrading**.

One tag covers everything this repository builds: the API, the two writers
(`deevnet-broker-account`, `deevnet-log-user`) and `deevnet-kit`.

## 0.20.2 (2026-11-12)

### Changed

- **A deleted tenant's name refuses every token for it** (CHG-0065), not only the token its row
  held. A tenant token whose name is not registered but was deleted is answered `401`, and an
  operator restore carrying one is `400`; the name comes back only through admission, which issues
  a new token. This covers tenants deleted before 0.20.0, whose token hashes were never kept.

### Upgrading

- Migration `0012_deleted_names.sql` seeds the deleted names from the audit log's `delete`
  entries, so every tenant ever deleted is covered from the first start. A deleted tenant that was
  admitted again is unaffected: while a name is registered, its row's token hash decides.

## 0.20.1 (2026-11-12)

### Fixed

- A tenant delete failed at the `dashboards` step (502) when the tenant had made a folder: the
  folder delete asked Grafana to force-delete alert rules, which a Grafana with alerting off, as
  the site runs it, refuses even to the server admin (403). Folders are now deleted plainly. The
  integration tests' Grafana now runs with alerting off too, which is how this was missed.

## 0.20.0 (2026-11-12)

### Changed

- **Deleting a tenant revokes its API token** (CHG-0065). Until now a deleted tenant's token still
  verified by its MAC and, with no registry row to compare against, was taken for a tenant restoring
  itself after a lost registry, so it could create the name again. The delete now records the
  token's hash in `revoked_tenant_tokens` in the same transaction that removes the row, and a
  revoked token is answered `401`, or `400` when an operator's restore carries it. A tenant admitted
  again under the name gets a new token. A restore after a genuinely lost registry is unchanged;
  the table is lost with it, so a token deleted before that loss would be accepted again.
- **Deleting a tenant deletes its Terraform state** (CHG-0065): every version and delete marker
  under `tenants/<name>/` in the state bucket, after the tenant's state-store user is removed. It
  used to stay in the bucket until the operator ran `make purge-tenant-state`. The purge refuses
  any prefix that is not a tenant's.
- **Deleting a tenant empties its Grafana organization** (CHG-0065): folders (with their alert
  rules), dashboards, library panels, snapshots and annotations go before the organization is
  renamed `deleted-<name>-<id>`. The renamed organization used to keep whatever the tenant had
  saved.

### Upgrading

- Migration `0011_revoked_tokens.sql` runs on start. A tenant deleted before this release left no
  hash behind, so this does not cover its token: the token can still create its name. The
  audit log's `delete` entries name those tenants.
- The API's MinIO user needs `s3:ListBucket` and `s3:ListBucketVersions` on the state bucket for
  prefix `tenants/*`, and `s3:DeleteObject` and `s3:DeleteObjectVersion` on `tenants/*`. Apply the
  `deevnet.mgmt` minio role that grants them **before** deploying this release; without them a
  tenant delete stops at the `state` step with a 502, and a second delete resumes it once the
  policy is in place.

## 0.19.0 (2026-11-09)

### Added

- `POST /v1/tenants/{name}/state-secret`, operator only, reissues a tenant's state-store secret
  (CHG-0060, 2026-10 review T2). It mints a new secret, records it, sets it on the store and
  returns it; the old one stops working. It is the way back in for a tenant that has lost the keys
  to its own state. The stored secret is still never returned. The tenant's Terraform state keeps
  the old secret, and a restore from that state would put it back, so a tenant given a new secret
  must not restore from its old state.

## 0.18.0 (2026-11-08)

### Added

- **A PKI of your own** (`deevnet-kit pki`, CHG-0056, ADR-0041 §3 and §4), the starter kit for
  leaving Deevnet. It runs the ceremony tools from `deevnet.mgmt` (`deevnet-pki-owner.sh`), which
  the image must carry at `/usr/local/sbin`.
  - `pki init --org ORG [--domain D]...` makes the owner's root on an encrypted USB stick and an
    issuing CA on the Pi. Nothing served changes. Until the switch, `export` and `env` hand out
    `trust-bundle.pem`, the root trusted now and the owner's, for every device and computer.
  - `pki switch` reissues the Pi's certificate from the owner's CA and moves every service onto
    the owner's root. It keeps the root it replaced as `previous-root.pem`. An extra name the
    owner's CA can't sign is left out and listed.
  - **On a Deevnet Pi, the tenant's names survive the switch.** `pki init` also permits the owner's
    CA `<tenant>.deevnet.net`, and `pki switch` keeps `mqtt`, `logs` and `grafana` under it, with
    their loopback mapping. A device that verified `mqtt.<tenant>.deevnet.net` verifies the same
    name afterwards, so only its trusted root changes. A new card for such a Pi takes
    `pki issuing --domain <tenant>.deevnet.net`.
  - `pki enroll DEVICE --out DIR [--csr FILE]` issues a device's certificate.
  - `pki issuing` makes a new card's issuing CA from the root on the stick, and says the next step is
    `pki switch`: the card's devices already trust that root.
  - Once on the owner's root, `regen-certs` renews from the owner's CA on the Pi alone.
  - The server certificate names `<host>.local`, `localhost`, loopback, the Pi's private
    addresses, and extra names under `.local` or the owner's domains. The bare host name is left
    out, because no name constraint covers a single label.

## 0.17.0 (2026-11-07)

### Added

- `OPENBAO_TENANT_SERVICE_CEL=true` signs tenants' server certificates through the Tenant Service
  CA's CEL role (`cel/sign/<role>`; tested on OpenBao 2.6.2) rather than its classic role. The CEL
  role, which Ansible writes, refuses a reserved tenant label, a request naming two tenants and a
  name of any other shape itself, so the secret store holds the line the API's checks hold
  (ADR-0040 §3, CHG-0059).

### Upgrading

- Off by default. Write the CEL role and grant the API `cel/sign/<role>` before turning it on.

## 0.16.0 (2026-11-07)

### Added

- `deevnet-kit cert install` takes a renewal for the key a Deevnet Pi already serves: what
  `deevnet_certificate` issues for the same key once sixty days remain. It must chain to the root
  the Pi already trusts and name `mqtt`, `logs` and `grafana`; the key is kept, and a pending
  request stays pending. `cert request` and a new key remain the other way to renew (#43).

### Changed

- The refusal of a reserved tenant name reads "it is a site, a global alias or a name the platform
  keeps": `mqtt` is a site broker's name, and there is no bus name. Only the message changed; the
  list is the same. The API needs no redeploy for the rest of this release.
- The repository is licensed Apache-2.0.

### Fixed

- `deevnet-kit cert install` reruns the dashboards step after its restarts, so Grafana's log data
  sources name `logs.<tenant>.deevnet.net` rather than `localhost`, which the certificate does not
  hold (#41).
- `deevnet-kit status` and `selftest` no longer warn on a Deevnet Pi that the certificate names
  none of its addresses, and suggest `regen-certs`, which refuses there. They warn instead when it
  is missing a name the Pi's services dial (#42).

## 0.15.0 (2026-10-25)

### Added

- `sites` on a certificate request: the sites to name it at, among `DEEVNET_CERTIFICATE_SITES`.
  Empty means this site alone.
- **A Deevnet Pi** (`deevnet-kit`, CHG-0056, ADR-0041 §2). `deevnet-kit cert request` makes a new
  key on the Pi and a signing request for the Tenant Service CA; `deevnet-kit cert install
  FULLCHAIN ROOT` installs what comes back, after checking it is for that key, chains to the root
  given, and names `mqtt`, `logs` and `grafana` under `<tenant>.deevnet.net`. From then on the
  Pi's own services dial those names, mapped to loopback in `/etc/hosts`, and trust the Deevnet
  Root; `kit.env` and `export` hand an app the names and `deevnet-root-ca.pem`. The card's own CA
  is kept as `tls/card-ca.pem`.

### Changed

- **A tenant's certificate names its service without a site, and its sites beside it**
  (CHG-0054, ADR-0040). The common name and first name is `<certificate>.<tenant>.deevnet.net`,
  then each further label the same way, then each label at each site, as
  `<label>.<tenant>.<site>.deevnet.net`. A certificate asked for again is reissued with the new
  names.
- **Tenant names that are sites, the bus name or a global alias are refused** at create and
  admission: `home`, `mobile`, `mgmt`, `dvnt`, `dvntm`, `device`, `mqtt`, `artifacts`.
- `device` is refused as a certificate label: it holds a tenant's device names.
- `deevnet-kit regen-certs` refuses on a Deevnet Pi, where it would sign with the card's CA.

### Upgrading

- `DEEVNET_CERTIFICATE_SITES` (optional, comma-separated): the sites a certificate may name.
  Unset means this site alone.
- The Tenant Service CA's signing role must allow names two labels under the root, not only
  under the site's zone: deevnet.mgmt sets it.
- Nothing changes for a card until `cert install` runs. After it, re-export each app's `kit.env`:
  its broker host and CA file change.

## 0.14.0 (2026-10-25)

### Added

- **`deevnet-api reseal`** moves every stored tenant secret to the current Transit key and exits
  (CHG-0036). It runs in the API's container with its environment:
  `podman exec deevnet-api /usr/local/bin/deevnet-api reseal`. It prints how many values moved,
  were already current, and opened under neither key, and fails if any did not open, so the
  previous key is not retired while a value still needs it. A second run moves nothing.
- `OPENBAO_TRANSIT_KEY_PREVIOUS`: the key being replaced. While it is set, a ciphertext the
  current key refuses is tried with it, so tenants keep working between the switch and the
  reseal.

### Upgrading

- To move to a new Transit key: set `OPENBAO_TRANSIT_KEY` to the new key and
  `OPENBAO_TRANSIT_KEY_PREVIOUS` to the old, deploy, run `reseal`, then unset the previous key.
  The API's policy needs decrypt on both keys meanwhile.

## 0.13.0 (2026-10-25)

### Changed

- **A sealed OpenBao is unavailable, not a lost secret** (CHG-0052, ADR-0042 §3). While OpenBao
  is sealed or unreachable, tenant work answers `503` with an error that says so, before
  anything changes. A stored secret is no longer marked unreadable, emptied or re-minted because
  of it: before, a reconcile against a sealed store would have replaced working log tokens, the
  dashboard password and Wi-Fi keys. A ciphertext OpenBao answers and refuses (a rebuilt Transit
  key) is still a lost secret, as before.
- A tenant token presented while OpenBao is sealed gets `503`, not `401`.
- `/readyz` reports `openbao` (`ok`, `sealed`, `uninitialized`, `unreachable`) and is `503`
  unless it is `ok`.
- **The API starts while OpenBao is sealed.** It used to exit when it could not read its backend
  credentials, and restart until OpenBao opened. It now serves readiness, answers `503` on `/v1`,
  and reads them as soon as OpenBao opens. A configuration error still stops it.

### Upgrading

- A deploy's readiness wait fails while OpenBao is sealed. The `deevnet_api` role says so in its
  message; unseal and run it again.

## 0.12.0 (2026-10-18)

### Added

- **Extra names and addresses on a Pi's server certificate** (`deevnet-kit`, CHG-0050). A Pi
  with names in a site's DNS, or about to move to a network where it will have another address,
  can have its certificate carry them first. `names=` in `deevnet-kit.txt` sets them on first
  boot; `deevnet-kit names [list | set | add | rm]` changes them later, and `regen-certs`
  applies them. They are kept in `/etc/deevnet-kit/names`, one a line. Wildcards are refused.

### Changed

- `deevnet-kit regen-certs` restarts Grafana as well as the broker and vmauth. Grafana presents
  the same certificate on 3000 and kept the old one until it was restarted.

### Upgrading

- Nothing changes for a card that sets no names. A card initialized on 0.11.0 or earlier can be
  given names with `deevnet-kit names set` and `regen-certs`; no reflash.

## 0.11.0 (2026-10-11)

### Added

- **Server certificates for tenants' own services** (ADR-0037, CHG-0047):
  `PUT`, `GET` and `DELETE /v1/tenants/{name}/certificates/{certificate}`, and `GET` of the list.
  A tenant sends a signing request for a label in its own zone; the site's Tenant Service CA, in
  OpenBao, signs a one-year server certificate, and it comes back with the chain a server
  presents. The request is read for its public key alone. Asking again returns the same
  certificate until sixty days before it expires. Nothing is revoked, and nothing renews by
  itself.
- A documentation site, https://deevnet.github.io/deevnet-provisioning-api/, with the API
  reference rendered from `api/openapi.yaml`.
- `api/openapi.yaml`, an OpenAPI 3.1 specification, as the contract. It replaces
  `docs/api-v1.md`, and tests fail when it and the code disagree on a route or a wire field.

### Upgrading

- Certificates are off until `OPENBAO_TENANT_SERVICE_MOUNT` names the Tenant Service CA's mount.
  A site without one needs to change nothing. A site with one adds the variable, and `update` on
  `<mount>/sign/tenant-service` to the service's OpenBao policy.
- The database gains a table, `tenant_certificates`, by migration `0010`. It runs at start.

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
