package tenant

import (
	"context"
	"errors"

	"golang.org/x/crypto/bcrypt"

	"github.com/deevnet/deevnet-provisioning-api/internal/brokeracct"
)

// Tenant MQTT broker accounts (ADR-0012 §3, §10; CHG-0016).
//
// The account reaches the broker through the account writer on the messaging
// VM, because the broker's auth database is not reachable from the network.
// This package does not know that: it calls BrokerWriter and the transport is
// somebody else's problem.

// bcryptCost is the work factor. 12 is what the plugin's own documented
// example uses, and the cost is paid by PostgreSQL at connect rather than by
// the broker - the database verifies with crypt(), so a slow hash does not
// spend the broker's cores (ADR-0012 §8).
const bcryptCost = 12

// BrokerAccountRequest is a tenant asking for an account.
type BrokerAccountRequest struct {
	Name string
	// Device is optional. Empty means a workload account; a named device must
	// belong to this tenant and be in trust class iot.
	Device string
	// Publish and Subscribe are patterns RELATIVE to the tenant's prefix. The
	// API prefixes them (ADR-0012 §10), so a tenant declares
	// "lightstand/+/scene" and never writes its own name.
	Publish   []string
	Subscribe []string
	// Password is set only on a restore: the tenant already holds the
	// authoritative copy and is putting it back after the API lost its own
	// (ADR-0012 §5). A tenant never chooses a new account's password.
	Password string
}

// IssuedBrokerAccount is the account plus the password, which is present only
// when this call minted or was given one.
type IssuedBrokerAccount struct {
	BrokerAccount
	// Password is the plaintext, returned once. Empty on a read, and empty
	// when a re-apply reused the hash already stored - there is nothing to
	// return in that case, because the API does not hold the plaintext.
	Password string
	// Username is what the broker will know this account as. Derived, so the
	// tenant can see it without being able to choose it.
	Username string
}

// CreateBrokerAccount issues or re-applies an account.
//
// The order is the part that matters. The hash is written to the registry
// BEFORE the writer is called, so a retry after an ambiguous failure sends the
// same hash and converges. Doing it the other way round would mint a new
// password on every retry and strand every device already flashed with the old
// one - the failure CHG-0013 records for Wi-Fi keys, in a new place.
func (s *Service) CreateBrokerAccount(ctx context.Context, tenantName string, req BrokerAccountRequest) (IssuedBrokerAccount, error) {
	if s.BrokerWriter == nil {
		return IssuedBrokerAccount{}, invalid("this API issues no broker accounts")
	}
	rec, err := s.Store.Get(ctx, tenantName)
	if err != nil {
		return IssuedBrokerAccount{}, err
	}
	if rec.Status != StatusReady {
		return IssuedBrokerAccount{}, invalid("tenant %q is %s", tenantName, rec.Status)
	}
	if !ValidWorkloadName(req.Name) {
		return IssuedBrokerAccount{}, invalid("account name must be 1-20 lowercase alphanumerics or dashes, starting with a letter")
	}
	if err := s.checkBrokerDevice(ctx, tenantName, req.Device); err != nil {
		return IssuedBrokerAccount{}, err
	}

	pub, err := brokeracct.PrefixPatterns(tenantName, "publish", req.Publish)
	if err != nil {
		return IssuedBrokerAccount{}, invalid("%s", err)
	}
	sub, err := brokeracct.PrefixPatterns(tenantName, "subscribe", req.Subscribe)
	if err != nil {
		return IssuedBrokerAccount{}, invalid("%s", err)
	}
	// The same rule the writer applies, applied here too, so an account that
	// grants nothing is a 400 from the API rather than a refusal from the
	// writer arriving as a 502 - which would read as the broker being down.
	if err := brokeracct.CheckGrant(pub, sub); err != nil {
		return IssuedBrokerAccount{}, invalid("%s", err)
	}

	existing, err := s.Store.GetBrokerAccount(ctx, tenantName, req.Name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return IssuedBrokerAccount{}, err
	}
	hash, plaintext, err := chooseBrokerSecret(req.Password, existing)
	if err != nil {
		return IssuedBrokerAccount{}, err
	}

	a := BrokerAccount{
		Tenant: tenantName, Name: req.Name, Device: req.Device,
		Publish: pub, Subscribe: sub,
		PasswordHash: hash, Status: StatusProvisioning,
	}
	// The row first. An account the broker holds is never one the registry has
	// no record of, and the hash a retry needs is already durable.
	a, err = s.Store.PutBrokerAccount(ctx, a)
	if err != nil {
		return IssuedBrokerAccount{}, err
	}
	s.audit(ctx, "broker-account-create", tenantName, map[string]any{
		"account": a.Name, "device": a.Device,
		"publish": pub, "subscribe": sub,
	})

	issued := IssuedBrokerAccount{BrokerAccount: a, Password: plaintext, Username: tenantName + "-" + a.Name}
	if err := s.BrokerWriter.Put(ctx, a); err != nil {
		s.logger().Error("writing broker account", "tenant", tenantName, "account", a.Name, "err", err)
		// The partial object goes back WITH the password, so a retry supplies
		// the same one rather than minting a second for the same devices.
		return issued, &StepError{Step: StepBroker, Err: err}
	}
	if err := s.Store.SetBrokerAccountStatus(ctx, tenantName, a.Name, StatusReady); err != nil {
		return issued, err
	}
	issued.Status = StatusReady
	return issued, nil
}

// checkBrokerDevice enforces ADR-0012 §3's pairing rule.
//
// An empty device is a workload account and needs no check: a workload reaches
// the broker over tenant_transit -> iot_backend, which the site declares, so
// the trust-class rule does not apply to it.
func (s *Service) checkBrokerDevice(ctx context.Context, tenantName, device string) error {
	if device == "" {
		return nil
	}
	d, err := s.Store.GetDevice(ctx, tenantName, device)
	if errors.Is(err, ErrNotFound) {
		return invalid("device %q is not registered to this tenant", device)
	}
	if err != nil {
		return err
	}
	// The standard declares no iot_vendor -> iot_backend path, so such an
	// account could never be used, and issuing one would imply a path the
	// segment is defined not to have (ADR-0012 §3).
	if d.TrustClass != "iot" {
		return invalid("device %q is in trust class %q; only iot devices get broker accounts, because the iot_vendor segment has no path to the broker",
			device, d.TrustClass)
	}
	return nil
}

// chooseBrokerSecret decides what the account's password should be: the one
// the tenant supplied, else the hash already stored, else a new one.
//
// Returning an empty plaintext for the middle case is deliberate. The API does
// not hold the plaintext - only the hash - so a re-apply of an unchanged
// account has nothing to return, and saying so is better than inventing one.
func chooseBrokerSecret(supplied string, existing BrokerAccount) (hash, plaintext string, err error) {
	if supplied != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(supplied), bcryptCost)
		if err != nil {
			return "", "", err
		}
		return string(h), supplied, nil
	}
	if existing.PasswordHash != "" {
		return existing.PasswordHash, "", nil
	}
	pw, err := randomPSK() // same alphabet as a Wi-Fi key: unambiguous and shell-safe
	if err != nil {
		return "", "", err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	if err != nil {
		return "", "", err
	}
	return string(h), pw, nil
}

// GetBrokerAccount returns one account. Never the password: the API does not
// have it.
func (s *Service) GetBrokerAccount(ctx context.Context, tenantName, name string) (IssuedBrokerAccount, error) {
	a, err := s.Store.GetBrokerAccount(ctx, tenantName, name)
	if err != nil {
		return IssuedBrokerAccount{}, err
	}
	return IssuedBrokerAccount{BrokerAccount: a, Username: tenantName + "-" + name}, nil
}

// ListBrokerAccounts returns a tenant's accounts.
func (s *Service) ListBrokerAccounts(ctx context.Context, tenantName string) ([]IssuedBrokerAccount, error) {
	accounts, err := s.Store.ListBrokerAccounts(ctx, tenantName)
	if err != nil {
		return nil, err
	}
	out := make([]IssuedBrokerAccount, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, IssuedBrokerAccount{BrokerAccount: a, Username: tenantName + "-" + a.Name})
	}
	return out, nil
}

// DeleteBrokerAccount revokes the account. Anything connected with it stays
// connected until it next reconnects: the broker caches ACLs per connection
// and evicts on disconnect (ADR-0012 §8), so revocation stops the next
// connection rather than the current one.
func (s *Service) DeleteBrokerAccount(ctx context.Context, tenantName, name string) error {
	if _, err := s.Store.GetBrokerAccount(ctx, tenantName, name); err != nil {
		return err
	}
	if s.BrokerWriter != nil {
		// The broker first, then the row. The other order would leave the
		// registry claiming an account the broker still honours.
		if err := s.BrokerWriter.Remove(ctx, tenantName, name); err != nil {
			return &StepError{Step: StepBroker, Err: err}
		}
	}
	s.audit(ctx, "broker-account-delete", tenantName, map[string]any{"account": name})
	return s.Store.DeleteBrokerAccount(ctx, tenantName, name)
}
