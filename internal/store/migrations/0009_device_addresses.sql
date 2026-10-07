-- Fixed addresses for tenants' devices (ADR-0035).
--
-- A device's address on the substrate's device network is allocated, unlike a
-- workload's, which is derived from the tenant's index: every tenant shares one
-- network, so there is no per-tenant block to derive from. The lowest free
-- address in the range the site sets aside is taken under the allocation lock,
-- and the tenant's own state remembers it for a restore.
--
-- The primary key is the device: one address per device. The foreign key is to
-- the device's registry row, so an address cannot outlive the device it was
-- reserved for - the service refuses to delete a device that still holds one,
-- and the cascade here is for a tenant delete, where the service has already
-- taken the reservations off the DHCP server.
--
-- UNIQUE (trust_class, address) is across tenants on purpose, the opposite of
-- the choice 0004 made for mac. There the substrate enforced nothing, so a
-- cross-tenant constraint would only have disclosed. Here two tenants cannot
-- both hold one address on a shared network, and the service answers a clash
-- without saying whose it is.
--
-- The MAC is not stored. It is the device's, in tenant_devices, and reading it
-- from there is what makes a hardware swap move the reservation.
CREATE TABLE tenant_device_addresses (
    tenant      text NOT NULL,
    device      text NOT NULL,
    trust_class text NOT NULL,
    address     text NOT NULL,
    status      text NOT NULL CHECK (status IN ('provisioning', 'ready', 'deleting')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, device),
    FOREIGN KEY (tenant, device) REFERENCES tenant_devices (tenant, name) ON DELETE CASCADE,
    UNIQUE (trust_class, address)
);
