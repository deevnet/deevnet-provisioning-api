package tenant

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
)

// Tenant Wi-Fi keys (ADR-0012 §3, amended 2026-09-18 to one key per tenant per
// trust class rather than one per device).
//
// A key is issued into the PPSK profile bound to its trust class's SSID, with
// that class's VLAN. The tenant chooses neither the SSID nor the VLAN, so no
// tenant network ever reaches the air; what it gets is a credential its devices
// can be flashed with, and the ability to revoke that credential without
// touching another tenant's devices.

// pskAlphabet is deliberately unambiguous and shell-safe: no 0/O, no 1/l/I, and
// no quoting, escaping or whitespace characters. This value is pasted into a
// Kconfig, a shell, YAML and possibly a QR code before it reaches a device, and
// it may be read off a screen by a person holding a soldering iron.
const pskAlphabet = "abcdefghjkmnpqrstuvwxyzACDEFGHJKLMNPQRSTUVWXYZ23456789"

// pskLength of 32 over that 54-symbol alphabet is about 184 bits, comfortably
// inside the controller's 8-63.
const pskLength = 32

// WiFiKeyRequest is a tenant asking for a key.
type WiFiKeyRequest struct {
	Name       string
	TrustClass string
	// PSK is set only on a restore: the tenant already holds the authoritative
	// copy and is putting it back after the API lost its own (ADR-0012 §5).
	// A tenant never chooses a new key's value.
	PSK string
}

// IssuedWiFiKey is a key plus the site facts a tenant needs to use it. SSID and
// VLAN are reported, not chosen; a tenant should never hardcode an SSID, and at
// the home site the same class is DVNT-IOT rather than DVNTM-IOT.
type IssuedWiFiKey struct {
	WiFiKey
	SSID string
	VLAN int
}

// CreateWiFiKey issues or re-applies a tenant's key for one trust class.
//
// Re-applying with the PSK the tenant holds is the restore path: the controller
// is made to match the devices, rather than the devices having to be reflashed
// to match a newly minted key.
func (s *Service) CreateWiFiKey(ctx context.Context, tenantName string, req WiFiKeyRequest) (IssuedWiFiKey, error) {
	if s.Wireless == nil {
		return IssuedWiFiKey{}, invalid("this API issues no Wi-Fi keys")
	}
	rec, err := s.Store.Get(ctx, tenantName)
	if err != nil {
		return IssuedWiFiKey{}, err
	}
	if rec.Status != StatusReady {
		return IssuedWiFiKey{}, invalid("tenant %q is %s", tenantName, rec.Status)
	}
	if !ValidWorkloadName(req.Name) {
		return IssuedWiFiKey{}, invalid("key name must be 1-20 lowercase alphanumerics or dashes, starting with a letter")
	}
	tc, ok := s.Site.TrustClass(req.TrustClass)
	if !ok {
		return IssuedWiFiKey{}, invalid("trust class %q is not served at this site; it serves %v",
			req.TrustClass, s.Site.TrustClassNames())
	}
	if req.PSK != "" && !ValidPSK(req.PSK) {
		return IssuedWiFiKey{}, invalid("psk must be 8 to 63 visible ASCII characters")
	}

	existing, err := s.Store.GetWiFiKey(ctx, tenantName, req.Name)
	switch {
	case errors.Is(err, ErrNotFound):
		// new key below
	case err != nil:
		return IssuedWiFiKey{}, err
	default:
		// Moving a key between trust classes would move every device already
		// holding it onto another VLAN, silently. The provider marks the field
		// RequiresReplace, but the rule belongs here: an API that depends on a
		// client to enforce it does not enforce it.
		if existing.TrustClass != req.TrustClass {
			return IssuedWiFiKey{}, invalid(
				"key %q is in trust class %q; a key cannot change class, because every device holding it would move VLAN. Use a new key",
				req.Name, existing.TrustClass)
		}
	}

	psk, err := choosePSK(req.PSK, existing)
	if err != nil {
		return IssuedWiFiKey{}, err
	}

	k := WiFiKey{
		Tenant:     tenantName,
		Name:       req.Name,
		TrustClass: req.TrustClass,
		PSK:        psk,
		Status:     StatusProvisioning,
	}
	// The row goes down first, so a key written to the controller is never one
	// the registry has no record of.
	k, err = s.Store.PutWiFiKey(ctx, k)
	if err != nil {
		return IssuedWiFiKey{}, err
	}
	s.audit(ctx, "wifi-key-create", tenantName, map[string]any{
		"key": k.Name, "trust_class": k.TrustClass, "vlan": tc.VLAN, "ssid": tc.SSID,
	})

	spec := WiFiKeySpec{SSID: tc.SSID, Name: tenantName + "-" + k.Name, PSK: psk, VLAN: tc.VLAN}
	if err := s.Wireless.EnsureKey(ctx, spec); err != nil {
		s.logger().Error("issuing wifi key", "tenant", tenantName, "key", k.Name, "err", err)
		return IssuedWiFiKey{WiFiKey: k, SSID: tc.SSID, VLAN: tc.VLAN}, &StepError{Step: StepWiFiKey, Err: err}
	}
	if err := s.Store.SetWiFiKeyStatus(ctx, tenantName, k.Name, StatusReady); err != nil {
		return IssuedWiFiKey{WiFiKey: k, SSID: tc.SSID, VLAN: tc.VLAN}, err
	}
	k.Status = StatusReady
	return IssuedWiFiKey{WiFiKey: k, SSID: tc.SSID, VLAN: tc.VLAN}, nil
}

// choosePSK decides what the key's password should be: the one the tenant
// supplied, else the one already stored, else a new one.
//
// A supplied secret wins over a stored one (ADR-0015 §4). Keeping the stored
// one when nothing is supplied is what makes re-applying an unchanged resource
// a no-op instead of a silent rotation that strands every flashed device.
func choosePSK(supplied string, existing WiFiKey) (string, error) {
	if supplied != "" {
		return supplied, nil
	}
	if existing.PSK != "" {
		return existing.PSK, nil
	}
	return randomPSK()
}

// randomPSK draws a password uniformly from pskAlphabet.
func randomPSK() (string, error) {
	out := make([]byte, pskLength)
	n := big.NewInt(int64(len(pskAlphabet)))
	for i := range out {
		v, err := rand.Int(rand.Reader, n)
		if err != nil {
			return "", err
		}
		out[i] = pskAlphabet[v.Int64()]
	}
	return string(out), nil
}

// GetWiFiKey returns one key, with the site facts that go with its class.
func (s *Service) GetWiFiKey(ctx context.Context, tenantName, name string) (IssuedWiFiKey, error) {
	k, err := s.Store.GetWiFiKey(ctx, tenantName, name)
	if err != nil {
		return IssuedWiFiKey{}, err
	}
	return s.withClass(k), nil
}

// ListWiFiKeys returns a tenant's keys.
func (s *Service) ListWiFiKeys(ctx context.Context, tenantName string) ([]IssuedWiFiKey, error) {
	keys, err := s.Store.ListWiFiKeys(ctx, tenantName)
	if err != nil {
		return nil, err
	}
	out := make([]IssuedWiFiKey, 0, len(keys))
	for _, k := range keys {
		out = append(out, s.withClass(k))
	}
	return out, nil
}

// DeleteWiFiKey revokes a key. Every device flashed with it stops associating,
// which is the point of the key being per tenant.
func (s *Service) DeleteWiFiKey(ctx context.Context, tenantName, name string) error {
	k, err := s.Store.GetWiFiKey(ctx, tenantName, name)
	if err != nil {
		return err
	}
	if err := s.removeKeyFromController(ctx, k); err != nil {
		return &StepError{Step: StepWiFiKey, Err: err}
	}
	s.audit(ctx, "wifi-key-delete", tenantName, map[string]any{"key": name, "trust_class": k.TrustClass})
	return s.Store.DeleteWiFiKey(ctx, tenantName, name)
}

// removeKeyFromController deletes the key from the wireless controller. A site
// that serves no trust classes, or no longer serves this one, leaves nothing to
// remove: the row is still dropped, because keeping a registry row for a key
// that cannot exist helps nobody.
func (s *Service) removeKeyFromController(ctx context.Context, k WiFiKey) error {
	if s.Wireless == nil {
		return nil
	}
	tc, ok := s.Site.TrustClass(k.TrustClass)
	if !ok {
		return nil
	}
	// The raw error: both callers wrap it as a StepError themselves, and one of
	// them is inside the delete step loop, which would otherwise nest two.
	return s.Wireless.RemoveKey(ctx, tc.SSID, k.Tenant+"-"+k.Name)
}

func (s *Service) withClass(k WiFiKey) IssuedWiFiKey {
	tc, _ := s.Site.TrustClass(k.TrustClass)
	return IssuedWiFiKey{WiFiKey: k, SSID: tc.SSID, VLAN: tc.VLAN}
}
