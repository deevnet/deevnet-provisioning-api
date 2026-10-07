package tenant

import (
	"context"
	"errors"
	"net/netip"
)

// Fixed device addresses (ADR-0035).
//
// A tenant's device joins a network the substrate owns and every tenant shares,
// and by default it leases whatever the pool gives it. A tenant that wants its
// device found at the same address every time asks for one here, for a device
// it has registered with a MAC. Three things then exist: a row, a reservation
// on the network's DHCP server, and the device's name in the tenant's own zone.
//
// The address is the substrate's and the name is the tenant's, so each is
// written where its owner keeps it and the API checks one against the other.
// Nothing is written to the substrate's zone, and no PTR is published: the
// reverse zone for the network belongs to the substrate (ADR-0035, open
// question 1).
//
// None of this is authorization. A reservation follows a MAC, and a MAC is
// copied by anyone on the segment (ADR-0020 §2).

// IssuedAddress is an address plus the name it was published under.
type IssuedAddress struct {
	DeviceAddress
	// FQDN is <device>.<tenant zone>.
	FQDN string
}

// CreateDeviceAddress reserves an address for a registered device, or
// re-applies one that already exists.
//
// requested is the address the tenant wants, or empty for the lowest free one.
// A restore sends the address the tenant's state remembers, which is how a
// device keeps its address across a lost registry.
func (s *Service) CreateDeviceAddress(ctx context.Context, tenantName, device, requested string) (IssuedAddress, error) {
	if s.Reservations == nil {
		return IssuedAddress{}, invalid("this API reserves no addresses")
	}
	rec, err := s.Store.Get(ctx, tenantName)
	if err != nil {
		return IssuedAddress{}, err
	}
	if rec.Status != StatusReady {
		return IssuedAddress{}, invalid("tenant %q is %s", tenantName, rec.Status)
	}
	d, err := s.Store.GetDevice(ctx, tenantName, device)
	if errors.Is(err, ErrNotFound) {
		return IssuedAddress{}, invalid("device %q is not registered", device)
	}
	if err != nil {
		return IssuedAddress{}, err
	}
	if d.MAC == "" {
		return IssuedAddress{}, invalid("device %q has no mac; an address is reserved for a MAC, so register it with one", device)
	}
	r, ok := s.Site.AddressRanges[d.TrustClass]
	if !ok {
		return IssuedAddress{}, invalid("this site reserves no addresses in trust class %q", d.TrustClass)
	}
	if requested != "" {
		addr, err := netip.ParseAddr(requested)
		if err != nil || !r.Contains(addr) {
			return IssuedAddress{}, invalid("address %q is not in the range tenants are given, %s to %s", requested, r.First, r.Last)
		}
		requested = addr.String()
	}

	existing, err := s.Store.GetDeviceAddress(ctx, tenantName, device)
	switch {
	case errors.Is(err, ErrNotFound):
		// The name is about to be published, and a workload or a record may
		// already be using it. Whichever came first keeps it.
		if err := s.nameIsFree(ctx, tenantName, device); err != nil {
			return IssuedAddress{}, err
		}
	case err != nil:
		return IssuedAddress{}, err
	default:
		// Moving a device's address in place would leave the old one reserved
		// until the write landed and both half-published if it did not. The
		// provider replaces the resource; the rule belongs here regardless.
		if requested != "" && requested != existing.Address {
			return IssuedAddress{}, invalid("device %q holds %s; remove that address before asking for another", device, existing.Address)
		}
	}

	a, err := s.Store.CreateDeviceAddress(ctx, DeviceAddress{
		Tenant:     tenantName,
		Device:     device,
		TrustClass: d.TrustClass,
		MAC:        d.MAC,
		Status:     StatusProvisioning,
	}, func(held []DeviceAddress) (string, error) {
		return pickAddress(r, s.Site.AddressQuota(), tenantName, d.MAC, requested, held)
	})
	if err != nil {
		return IssuedAddress{}, err
	}
	a.MAC = d.MAC
	s.audit(ctx, "device-address-create", tenantName, map[string]any{
		"device": device, "trust_class": a.TrustClass, "address": a.Address, "mac": a.MAC,
	})
	return s.pushAddress(ctx, a, existing.Address == "")
}

// pushAddress writes the reservation and the name, then marks the row ready.
// fresh is true when the row was made by this call: only then is a conflict on
// the DHCP server answered by taking the row back, because an address that was
// already working is not withdrawn on a later failure.
func (s *Service) pushAddress(ctx context.Context, a DeviceAddress, fresh bool) (IssuedAddress, error) {
	out := IssuedAddress{DeviceAddress: a, FQDN: a.Device + "." + s.Site.Zone(a.Tenant)}
	if err := s.Reservations.EnsureReservation(ctx, s.reservation(a)); err != nil {
		s.logger().Error("reserving address", "tenant", a.Tenant, "device", a.Device, "err", err)
		// The server already holds this MAC or address for someone the registry
		// does not know: a substrate host, or a reservation made by hand. That
		// is not a failure to retry, so no half-made row is left behind.
		if errors.Is(err, ErrAddressConflict) {
			if fresh {
				if derr := s.Store.DeleteDeviceAddress(ctx, a.Tenant, a.Device); derr != nil {
					s.logger().Error("withdrawing address", "tenant", a.Tenant, "device", a.Device, "err", derr)
				}
			}
			return IssuedAddress{}, ErrAddressConflict
		}
		return out, &StepError{Step: StepAddress, Err: err}
	}
	rec, err := s.Store.Get(ctx, a.Tenant)
	if err != nil {
		return out, err
	}
	if err := s.DNS.EnsureRecords(ctx, s.Site.Zone(a.Tenant), s.Site.Numbering(rec.Index).ReverseZone,
		[]DNSRecord{{Name: a.Device, Address: a.Address}}); err != nil {
		s.logger().Error("publishing device", "tenant", a.Tenant, "device", a.Device, "err", err)
		return out, &StepError{Step: StepDNS, Err: err}
	}
	if err := s.Store.SetDeviceAddressStatus(ctx, a.Tenant, a.Device, StatusReady); err != nil {
		return out, err
	}
	out.Status = StatusReady
	return out, nil
}

// pickAddress decides which address a device gets. held is every address in the
// trust class, across all tenants.
func pickAddress(r AddressRange, quota int, tenantName, mac, requested string, held []DeviceAddress) (string, error) {
	taken := map[string]bool{}
	mine := 0
	for _, h := range held {
		// One reservation per MAC on a network, whoever holds it. The DHCP
		// server would refuse a second, and the error must not say whose the
		// first is.
		if h.MAC == mac {
			return "", ErrAddressConflict
		}
		taken[h.Address] = true
		if h.Tenant == tenantName {
			mine++
		}
	}
	if mine >= quota {
		return "", ErrAddressQuota
	}
	if requested != "" {
		if taken[requested] {
			return "", ErrAddressConflict
		}
		return requested, nil
	}
	for addr := r.First; r.Contains(addr); addr = addr.Next() {
		if !taken[addr.String()] {
			return addr.String(), nil
		}
	}
	return "", ErrAddressesExhausted
}

// nameIsFree refuses a device name a workload or a published record already
// uses in the tenant's zone.
func (s *Service) nameIsFree(ctx context.Context, tenantName, name string) error {
	if _, err := s.Store.GetWorkload(ctx, tenantName, name); err == nil {
		return invalid("the name %q is a workload's; a device with an address is published under its own name", name)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	recs, err := s.Store.ListRecords(ctx, tenantName)
	if err != nil {
		return err
	}
	for _, r := range recs {
		if r.Name == name {
			return invalid("the name %q is already a published record; a device with an address is published under its own name", name)
		}
	}
	return nil
}

// deviceHoldsName refuses a workload or record name that a device's address is
// already published under.
func (s *Service) deviceHoldsName(ctx context.Context, tenantName, name string) error {
	if _, err := s.Store.GetDeviceAddress(ctx, tenantName, name); err == nil {
		return invalid("the name %q is published for a device's address", name)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}

// GetDeviceAddress returns a device's address.
func (s *Service) GetDeviceAddress(ctx context.Context, tenantName, device string) (IssuedAddress, error) {
	a, err := s.Store.GetDeviceAddress(ctx, tenantName, device)
	if err != nil {
		return IssuedAddress{}, err
	}
	return IssuedAddress{DeviceAddress: a, FQDN: a.Device + "." + s.Site.Zone(a.Tenant)}, nil
}

// DeleteDeviceAddress gives the address back. The device keeps working: it
// leases from the pool like any other at its next renewal.
func (s *Service) DeleteDeviceAddress(ctx context.Context, tenantName, device string) error {
	rec, err := s.Store.Get(ctx, tenantName)
	if err != nil {
		return err
	}
	a, err := s.Store.GetDeviceAddress(ctx, tenantName, device)
	if err != nil {
		return err
	}
	// A name left pointing at an address the tenant no longer holds would point
	// at whichever tenant is given it next.
	recs, err := s.Store.ListRecords(ctx, tenantName)
	if err != nil {
		return err
	}
	for _, r := range recs {
		if r.Address == a.Address {
			return invalid("record %q still points at %s; remove it first", r.Name, a.Address)
		}
	}
	if err := s.removeReservation(ctx, a); err != nil {
		return &StepError{Step: StepAddress, Err: err}
	}
	if err := s.DNS.RemoveRecords(ctx, s.Site.Zone(tenantName), s.Site.Numbering(rec.Index).ReverseZone,
		[]DNSRecord{{Name: a.Device, Address: a.Address}}); err != nil {
		return &StepError{Step: StepDNS, Err: err}
	}
	s.audit(ctx, "device-address-delete", tenantName, map[string]any{"device": device, "address": a.Address})
	return s.Store.DeleteDeviceAddress(ctx, tenantName, device)
}

// removeReservation deletes the reservation from the DHCP server. A site that
// no longer reserves addresses leaves nothing to remove, and the row is still
// dropped - the same reasoning as removeKeyFromController.
//
// The raw error: both callers wrap it as a StepError themselves.
func (s *Service) removeReservation(ctx context.Context, a DeviceAddress) error {
	if s.Reservations == nil {
		return nil
	}
	return s.Reservations.RemoveReservation(ctx, reservationDescription(a.Tenant, a.Device))
}

// ensureAddresses puts every one of a tenant's reservations and device names
// back: the repair after the router is rebuilt, which loses them, since
// inventory does not hold them and so cannot restore them.
func (s *Service) ensureAddresses(ctx context.Context, rec Record) error {
	addrs, err := s.Store.ListDeviceAddresses(ctx, rec.Name)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if _, ok := s.Site.AddressRanges[a.TrustClass]; !ok {
			continue
		}
		if err := s.Reservations.EnsureReservation(ctx, s.reservation(a)); err != nil {
			return err
		}
		if err := s.DNS.EnsureRecords(ctx, s.Site.Zone(rec.Name), s.Site.Numbering(rec.Index).ReverseZone,
			[]DNSRecord{{Name: a.Device, Address: a.Address}}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) reservation(a DeviceAddress) Reservation {
	return Reservation{
		Subnet:  s.Site.AddressRanges[a.TrustClass].Subnet.String(),
		Address: a.Address,
		MAC:     a.MAC,
		// What a DHCP client is told its name is. The tenant comes first so two
		// tenants' devices of the same name stay apart in the server's leases.
		Hostname:    a.Tenant + "-" + a.Device,
		Description: reservationDescription(a.Tenant, a.Device),
	}
}

// reservationDescription is the API's mark on a reservation, in the form the
// resolver forwards already use. Inventory's reservations start "Ansible
// managed", and each writer leaves the other's alone.
func reservationDescription(tenantName, device string) string {
	return "Deevnet API - " + tenantName + "/" + device
}

// holdsAddress reports whether address is one the tenant has reserved, which is
// what lets it publish further names for that device.
func (s *Service) holdsAddress(ctx context.Context, tenantName, address string) (bool, error) {
	addrs, err := s.Store.ListDeviceAddresses(ctx, tenantName)
	if err != nil {
		return false, err
	}
	for _, a := range addrs {
		if a.Address == address {
			return true, nil
		}
	}
	return false, nil
}
