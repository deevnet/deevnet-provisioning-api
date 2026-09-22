package tenant

import (
	"context"
)

// The tenant's users in the log store (ADR-0027 §2, CHG-0020).
//
// This is a backend step rather than a resource of its own: a tenant does not
// ask for log tokens any more than it asks for a TSIG key. It gets them when it
// is created, and they are re-asserted on every reconcile.
//
// Unlike broker accounts there is nothing to name and nothing to list. One
// tenant has exactly one pair, which is why they live in Secrets beside the
// TSIG and state secrets rather than in a table of their own.

// ensureLogTokens writes the tenant's users into the store, minting the pair
// first if the registry holds none.
//
// A tenant created before the store existed has no tokens, and neither has one
// whose secrets would not open after a Transit rebuild (ADR-0016 §6). Both are
// repaired the same way: mint a fresh pair and tell the store. Nothing is lost
// by doing so, because the store is *told* what the token is - unlike a TSIG
// key, where the tenant's own copy is the authority.
func (s *Service) ensureLogTokens(ctx context.Context, rec Record) error {
	if s.LogWriter == nil {
		return nil
	}
	if rec.Secrets.LogIngest == "" || rec.Secrets.LogRead == "" {
		ingest, read, err := logTokens()
		if err != nil {
			return err
		}
		secrets := rec.Secrets
		secrets.LogIngest, secrets.LogRead = ingest, read
		if err := s.Store.SetSecrets(ctx, rec.Name, secrets); err != nil {
			return err
		}
		rec.Secrets = secrets
	}
	return s.LogWriter.Put(ctx, LogTenant{
		Name:        rec.Name,
		Index:       rec.Index,
		IngestToken: rec.Secrets.LogIngest,
		ReadToken:   rec.Secrets.LogRead,
	})
}

// removeLogTokens takes the tenant's users out of the store.
//
// The tokens themselves go with the registry row. What matters here is that the
// store stops honouring them first: a row deleted while the store still held
// the user would leave a working credential belonging to nobody, which is the
// same reasoning that removes a tenant's Wi-Fi keys before its record.
func (s *Service) removeLogTokens(ctx context.Context, rec Record) error {
	if s.LogWriter == nil {
		return nil
	}
	return s.LogWriter.Remove(ctx, rec.Name, rec.Index)
}
