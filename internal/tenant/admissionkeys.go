package tenant

import (
	"context"
	"errors"
	"time"
)

// Admission keys (ADR-0029 §1).
//
// A tenant developer needs the tenant developer network to reach the API at
// all, so the first key on it cannot come from the tenant's own apply: it comes
// out of admission, with the enrollment token. It is one PPSK key in the
// admission class's profile, named "<tenant>-admission" - the name the tenant's
// own key "admission" carries in the controller, which is what lets it become
// one when the tenant creates itself. Until then this table holds it, because a
// tenant key needs a tenant.

// AdmissionKeyName is the name the admission key takes among the tenant's own
// keys once the tenant exists.
const AdmissionKeyName = "admission"

// AdmissionKey is a key issued with an admission, for a tenant not yet created.
type AdmissionKey struct {
	Tenant     string
	PSK        string
	MAC        string // normalized, or empty
	Unreadable bool
	CreatedAt  time.Time
}

// AdmissionWiFi is what an admission hands the tenant developer with the token.
type AdmissionWiFi struct {
	SSID string
	PSK  string
	MAC  string
}

// issueAdmissionKey mints a new key for name, replacing any earlier one: a
// repeated admission is how an expired or lost one is replaced, and the old
// key must stop working when the new one is handed over.
func (s *Service) issueAdmissionKey(ctx context.Context, name, mac string) (*AdmissionWiFi, error) {
	if s.Site.AdmissionClass == "" || s.Wireless == nil {
		return nil, nil
	}
	tc, ok := s.Site.TrustClass(s.Site.AdmissionClass)
	if !ok {
		return nil, invalid("admission class %q is not served at this site", s.Site.AdmissionClass)
	}
	psk, err := randomPSK()
	if err != nil {
		return nil, err
	}
	// The row goes down first, so a key in the controller is never one the
	// registry has no record of - the same order CreateWiFiKey keeps.
	if err := s.Store.PutAdmissionKey(ctx, AdmissionKey{Tenant: name, PSK: psk, MAC: mac}); err != nil {
		return nil, err
	}
	spec := WiFiKeySpec{SSID: tc.SSID, Name: name + "-" + AdmissionKeyName, PSK: psk, VLAN: tc.VLAN}
	if mac != "" {
		spec.MAC = ControllerMAC(mac)
	}
	if err := s.Wireless.EnsureKey(ctx, spec); err != nil {
		s.logger().Error("issuing admission key", "tenant", name, "err", err)
		return nil, &StepError{Step: StepWiFiKey, Err: err}
	}
	return &AdmissionWiFi{SSID: tc.SSID, PSK: psk, MAC: mac}, nil
}

// RevokeAdmission withdraws an admission that was never used: its key stops
// working. The enrollment token itself is left to expire - a wrapped token is
// not recalled here - so revoking takes away the way onto the tenant developer
// network, not the token.
func (s *Service) RevokeAdmission(ctx context.Context, name string) error {
	k, err := s.Store.GetAdmissionKey(ctx, name)
	if err != nil {
		return err
	}
	if tc, ok := s.Site.TrustClass(s.Site.AdmissionClass); ok && s.Wireless != nil {
		if err := s.Wireless.RemoveKey(ctx, tc.SSID, name+"-"+AdmissionKeyName); err != nil {
			return &StepError{Step: StepWiFiKey, Err: err}
		}
	}
	s.audit(ctx, "admission-revoke", name, map[string]any{"bound": k.MAC != ""})
	return s.Store.DeleteAdmissionKey(ctx, name)
}

// adoptAdmissionKey makes the admission key one of the tenant's own, named
// "admission", once the tenant exists. From then on it is revoked, listed and
// deleted like any other key, and goes with the tenant. The controller entry
// already carries the right name, so nothing there changes.
func (s *Service) adoptAdmissionKey(ctx context.Context, name string) error {
	k, err := s.Store.GetAdmissionKey(ctx, name)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := s.Store.PutWiFiKey(ctx, WiFiKey{
		Tenant: name, Name: AdmissionKeyName, TrustClass: s.Site.AdmissionClass,
		PSK: k.PSK, MAC: k.MAC, Status: StatusReady,
	}); err != nil {
		return err
	}
	return s.Store.DeleteAdmissionKey(ctx, name)
}
