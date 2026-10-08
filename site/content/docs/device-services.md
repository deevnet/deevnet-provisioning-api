---
title: "Device Services"
weight: 4
---

# Device services

**A tenant's devices get four things from the API: a registry entry, a fixed address, a Wi-Fi
key and a broker account.** Each is its own resource, and none implies another. The
[API Reference](/docs/reference/) has every field; this page is what the fields do not say.

## Registry

**A registry entry is identity, not authorization.** Registering a device grants it nothing. What
a device may consume is carried by a credential it proves
([ADR-0020](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/edge-devices/0020-direct-device-access-to-tenant-services/) §2), and this resource
issues none. Nor does a device reach its tenant's network.

- **The entry is the device's identity.** A tenant's device takes no substrate host record and is
  named in its owner's own zone.
- **`mac` is recorded, never enforced.** A MAC is trivially spoofed on a shared segment, so two
  tenants may record the same one. It is used for one thing, a fixed address.
- **A device cannot change trust class.** Its SSID, its VLAN and any service grants would all move
  at once under an unchanged name. Register it under a new name instead.
- **Deregistering does not disconnect.** The device keeps whatever Wi-Fi key it was flashed with,
  because that key belongs to the tenant rather than to the device.
- **`iot_vendor` devices are registerable.** They are refused a broker account, not an identity.
- **Registration writes to no backend**, so a site without a wireless controller still keeps a
  device registry.

## Fixed addresses

**A fixed address is allocated, not derived, because every tenant shares the device network.**
The address comes from the part of that network set aside for tenants, above the substrate's own
hosts and below the dynamic pool
([ADR-0035](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/edge-devices/0035-fixed-address-for-a-tenant-device/)).

- **The tenant's state remembers the address** and sends it back on a restore, which is how a
  device keeps its address across a lost registry.
- **The reservation follows the device's registered MAC.** There is one source for it, the
  device's own entry; changing the MAC there moves the reservation.
- **The device's name is published with it**, as `<device>.<tenant zone>`, and removed with it. No
  PTR is published: the reverse zone for that network is the substrate's.
- **A conflict never says who holds what.** A taken address or MAC answers `409` with no owner,
  because the network is shared.
- **A tenant has a share of the range**, 16 addresses unless the site says otherwise.
- **Giving an address back does not disconnect the device.** It leases from the pool at its next
  renewal.
- **A site that sets no range aside reserves none**, and the routes answer `400` with that reason.

## Wi-Fi keys

**One key serves every device a tenant flashes with it.** The key is per tenant per trust class;
the substrate does not know those devices individually.

- **A tenant never picks a VLAN.** The SSID and VLAN come from the trust class, which is what
  keeps a tenant network off the air.
- **`ssid` is reported so nothing hardcodes one.** The same trust class is a different SSID at
  another site.
- **Issuing again keeps the key.** A new one would stop every device flashed with the old one.
- **A read never returns the `psk`.** `secrets_stored` says whether the API's copy is still
  readable; when it is `false`, issue the key again with the `psk` the tenant holds.
- **`mac` binds a key to one client.** It suits the tenant developer network, one key per
  computer; a key shared by many devices is left unbound.

**The wireless controller keeps one placeholder entry in an otherwise empty key profile.** The
controller refuses to let a profile reach zero keys, so when the last real key is revoked the API
leaves an entry named `DEEVNET-PLACEHOLDER-DO-NOT-USE`. Its password is generated, returned to
nobody and stored nowhere, and it is removed the moment a real key is issued.

## Broker accounts

**A broker account is one MQTT login, for one device or one workload.** The tenant chooses its
name and topic patterns; the API chooses the username and password
([ADR-0012](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/tenant-model/0012-iot-platform-api/) §3, §8, §10).

### Topic confinement

**Patterns are written relative to the tenant, and the API writes the prefix.** A tenant declares
`lightstand/+/scene` and never its own name; the answer carries the absolute form, which is what
the broker enforces.

- **Naming another tenant does not escape.** For tenant `eds`, `tdemo/secrets/#` becomes
  `eds/tdemo/secrets/#`: a topic inside `eds` that happens to be named after someone else.
- **`#` means the tenant's own tree** and no more.
- **A pattern that cannot be prefixed is refused**: a leading `/`, a `$SYS` filter, a `%`, or
  a `#` that is not the last level.
- **One direction may be empty.** A sensor only publishes; a collector only subscribes. Both empty
  is refused.

### The log level

**The level `log`, immediately under the tenant's prefix, is reserved for device logs**
([ADR-0027](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/platform-services/0027-tenant-log-store/) §3). The substrate collects them there,
so a grant under it means one thing only.

| | May publish under `log/` | May subscribe under `log/` |
|---|---|---|
| a **device** account | exactly `log/<its own device>` | no |
| a **workload** account | no | yes, its own tenant's |

The rule covers the topic space, not the spelling: `#` and `+/stand-1` reach into the log space
without naming it, and are refused for a device account just as `log/#` is. A workload with logs
of its own ships them to the log store with the tenant's ingest token.

### Passwords

**The API holds a hash of the password and never the password.** The tenant's own state is the
only copy.

- **Issuing again returns no `password`.** There is nothing to return.
- **`password` is supplied only to restore** an account the tenant already holds. The broker is
  then made to match the devices.
- **A failed create still returns the password**, in the `502` body, so a retry supplies the same
  one and does not strand devices already flashed with it.
- **The hash is recorded before the broker is written**, so a retry after an ambiguous failure
  sends the same hash and converges.

### Revocation

**Revocation stops the next connection, not the current one.** The broker caches a connection's
permissions and drops them on disconnect, so anything connected stays connected until it
reconnects.

### How an account reaches the broker

**The broker's account database is not reachable from the network.** The API sends one request
over SSH to a writer program on the messaging host, bound to a single key that can run nothing
else. The API never speaks to the database.
