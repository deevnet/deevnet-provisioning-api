package tenant

import (
	"context"
	"errors"
)

// The tenant device registry (ADR-0012 §3).
//
// ADR-0020's implementation notes order this first: until devices exist as
// state there is nothing to record what a device may consume in, so the
// contract's §2 (a credential it proves) and §5 (every device-facing service
// authenticates per device) have nothing to draw on.
//
// What a registry entry is: a tenant's own name for one of its devices, and the
// trust class that device attaches under. What it is not: a network object. A
// device takes no substrate host record and no substrate DNS name. It leases
// from its class's pool, unless its tenant reserves it a fixed address, which
// is a separate thing built on this entry (addresses.go, ADR-0035).
//
// Registering calls no backend. A Wi-Fi key has to reach the wireless
// controller before it means anything; a device entry means something the
// moment it is written, because it is a fact about the tenant's own estate.
// The one backend call here is the reservation of a device that already holds
// an address and whose MAC has just changed.

// DeviceRequest is a tenant registering one of its devices.
type DeviceRequest struct {
	Name       string
	TrustClass string
	// MAC is optional. See Device.MAC: it is never an authorization input, and
	// is needed only by a device that is to hold a fixed address.
	MAC string
}

// CreateDevice registers a device, or re-applies one that already exists.
//
// Re-applying is a no-op except for the MAC, which is the one field a tenant
// may correct in place: swapping the hardware behind a name is an inventory
// change, not a new device. A device that holds a fixed address takes it along:
// the reservation moves to the new MAC, so the replacement is found where the
// old one was.
func (s *Service) CreateDevice(ctx context.Context, tenantName string, req DeviceRequest) (Device, error) {
	rec, err := s.Store.Get(ctx, tenantName)
	if err != nil {
		return Device{}, err
	}
	if rec.Status != StatusReady {
		return Device{}, invalid("tenant %q is %s", tenantName, rec.Status)
	}
	if !ValidWorkloadName(req.Name) {
		return Device{}, invalid("device name must be 1-20 lowercase alphanumerics or dashes, starting with a letter")
	}
	if _, ok := s.Site.TrustClass(req.TrustClass); !ok {
		return Device{}, invalid("trust class %q is not served at this site; it serves %v",
			req.TrustClass, s.Site.TrustClassNames())
	}
	mac := ""
	if req.MAC != "" {
		var ok bool
		if mac, ok = NormalizeMAC(req.MAC); !ok {
			return Device{}, invalid("mac %q is not a MAC address", req.MAC)
		}
	}

	existing, err := s.Store.GetDevice(ctx, tenantName, req.Name)
	switch {
	case errors.Is(err, ErrNotFound):
		// new device below
	case err != nil:
		return Device{}, err
	default:
		// A device's trust class decides which SSID it joins, which VLAN it
		// lands on, and later which services it may be granted. Changing it
		// under an unchanged name would re-scope all three silently. The
		// provider marks the field RequiresReplace, but the rule belongs here:
		// an API that depends on a client to enforce it does not enforce it.
		// The same reasoning as CreateWiFiKey.
		if existing.TrustClass != req.TrustClass {
			return Device{}, invalid(
				"device %q is in trust class %q; a device cannot change class, because its SSID, VLAN and any service grants would all move. Register it under a new name",
				req.Name, existing.TrustClass)
		}
	}

	// A device that holds an address has a reservation made for its MAC, so a
	// changed MAC is a changed reservation - checked before anything is written.
	held, err := s.Store.GetDeviceAddress(ctx, tenantName, req.Name)
	holds := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Device{}, err
	}
	moved := holds && existing.MAC != mac
	if moved {
		if mac == "" {
			return Device{}, invalid("device %q holds the address %s, which is reserved for its mac; remove the address before clearing the mac",
				req.Name, held.Address)
		}
		if s.Reservations == nil {
			return Device{}, invalid("this API reserves no addresses")
		}
		others, err := s.Store.ListClassAddresses(ctx, held.TrustClass)
		if err != nil {
			return Device{}, err
		}
		for _, o := range others {
			if o.MAC == mac && (o.Tenant != tenantName || o.Device != req.Name) {
				return Device{}, ErrAddressConflict
			}
		}
	}

	d, err := s.Store.PutDevice(ctx, Device{
		Tenant:     tenantName,
		Name:       req.Name,
		TrustClass: req.TrustClass,
		MAC:        mac,
		Status:     StatusReady,
	})
	if err != nil {
		return Device{}, err
	}
	s.audit(ctx, "device-create", tenantName, map[string]any{
		"device": d.Name, "trust_class": d.TrustClass, "mac": d.MAC,
	})
	if moved {
		held.MAC = d.MAC
		if err := s.Store.SetDeviceAddressStatus(ctx, tenantName, d.Name, StatusProvisioning); err != nil {
			return d, err
		}
		if _, err := s.pushAddress(ctx, held, false); err != nil {
			return d, err
		}
	}
	return d, nil
}

// GetDevice returns one of a tenant's devices.
func (s *Service) GetDevice(ctx context.Context, tenantName, name string) (Device, error) {
	return s.Store.GetDevice(ctx, tenantName, name)
}

// ListDevices returns a tenant's devices.
func (s *Service) ListDevices(ctx context.Context, tenantName string) ([]Device, error) {
	return s.Store.ListDevices(ctx, tenantName)
}

// DeleteDevice removes a device from the registry.
//
// This deregisters; it does not disconnect. The device keeps whatever Wi-Fi key
// it was flashed with, because that key is the tenant's, not the device's, and
// revoking it would strand every other device flashed with it (ADR-0012 §3, as
// amended for CHG-0013). What deregistration removes is the device's standing
// to be issued anything of its own.
func (s *Service) DeleteDevice(ctx context.Context, tenantName, name string) error {
	d, err := s.Store.GetDevice(ctx, tenantName, name)
	if err != nil {
		return err
	}
	// The address goes first, by its own route: dropping the row here would
	// leave the reservation on the DHCP server with nothing to say whose it is.
	if a, err := s.Store.GetDeviceAddress(ctx, tenantName, name); err == nil {
		return invalid("device %q holds the address %s; remove the address first", name, a.Address)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	s.audit(ctx, "device-delete", tenantName, map[string]any{
		"device": name, "trust_class": d.TrustClass,
	})
	return s.Store.DeleteDevice(ctx, tenantName, name)
}
