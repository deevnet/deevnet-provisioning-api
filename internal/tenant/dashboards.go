package tenant

import (
	"context"
	"errors"
)

// The tenant's organisation in the dashboard server (ADR-0024, CHG-0024).
//
// A backend step, like the log tokens and for the same reason: a tenant does
// not ask for a dashboard login, it has one. It runs after the log store step
// because the data sources carry the tenant's log read token, and there is
// nothing for them to carry before that step has minted it.

// ensureDashboards writes the tenant's organisation, login and data sources,
// minting the login's password first if the registry holds none.
//
// The server is told what the password is, so a missing or unreadable one is
// repaired by minting a new one - the same reasoning as ensureLogTokens. The
// tenant learns the new one from the response, as it learns its log tokens.
func (s *Service) ensureDashboards(ctx context.Context, rec Record) error {
	if s.Dashboards == nil {
		return nil
	}
	if rec.Secrets.LogRead == "" {
		// The log step runs first and mints this. Reaching here without one
		// means the site has dashboards and no log store, which would give the
		// tenant data sources that authenticate as nobody.
		return errors.New("the tenant has no log read token for its data sources; the site needs a log store before dashboards")
	}
	if rec.Secrets.DashboardPassword == "" {
		pw, err := randomHex(24)
		if err != nil {
			return err
		}
		secrets := rec.Secrets
		secrets.DashboardPassword = pw
		if err := s.Store.SetSecrets(ctx, rec.Name, secrets); err != nil {
			return err
		}
		rec.Secrets = secrets
	}
	org, err := s.Dashboards.Ensure(ctx, DashTenant{
		Name:      rec.Name,
		Index:     rec.Index,
		Password:  rec.Secrets.DashboardPassword,
		ReadToken: rec.Secrets.LogRead,
	})
	if err != nil {
		return err
	}
	if org != rec.DashboardOrg {
		return s.Store.SetDashboardOrg(ctx, rec.Name, org)
	}
	return nil
}

// removeDashboards takes the tenant's login and organisation out of the server
// before the log tokens go: its data sources hold the read token, and removing
// them first means nothing is left holding a credential that is about to stop
// working anyway.
func (s *Service) removeDashboards(ctx context.Context, rec Record) error {
	if s.Dashboards == nil {
		return nil
	}
	return s.Dashboards.Remove(ctx, rec.Name)
}
