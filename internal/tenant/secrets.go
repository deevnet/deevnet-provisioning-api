package tenant

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Tenant runtime secrets in the tenant's own OpenBao namespace (ADR-0021,
// CHG-0067). An optional service: a site that does not offer it leaves
// Service.TenantSecrets nil, and its routes answer ErrSecretsNotOffered.
//
// Three rules carry the weight:
//
//   - The API is in the write path only. It writes a value into the tenant's
//     KV mount and keeps the path and the tenant's version, never the value.
//     Its OpenBao policy has no read on data/, so it could not hand one back
//     if it tried. A read reports presence and version.
//   - What OpenBao holds is always a copy (ADR-0021 §3). The tenant's
//     repository is the authoritative one, so after an OpenBao rebuild a read
//     reports the secret absent and the next apply writes it again.
//   - Each reader is one workload's AppRole, bound to that workload's address,
//     with a policy that reads exactly the paths the tenant named for it.
//     Revoking it deletes the AppRole AND its policy: deleting the AppRole
//     alone stops new logins but leaves a token already issued working
//     (ADR-0021 §5).

const (
	// StepSecrets is the tenant's namespace with its KV and AppRole mounts.
	StepSecrets = "secrets"

	// SecretsMount and AppRoleMount are the two mounts in each tenant's
	// namespace (ADR-0021 §1). The tenant enables nothing else there.
	SecretsMount = "secrets"
	AppRoleMount = "approle"

	maxSecretPathLen   = 128
	maxReaderPaths     = 32
	readerPolicyPrefix = "reader-"
)

var (
	// ErrSecretsNotOffered: the site does not offer tenant secrets.
	ErrSecretsNotOffered = errors.New("this site does not offer tenant secrets")
	// ErrAbsent is something OpenBao does not hold: a secret or an AppRole
	// after a rebuild, or a namespace deleted by hand. It is not ErrNotFound,
	// which is the registry's; the service decides what each one means.
	ErrAbsent = errors.New("not present in OpenBao")

	secretSegment = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)
	readerName    = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
)

// SecretsBackend is OpenBao, administering tenants' namespaces. Every call
// that takes ns works inside that namespace; the API's policy reaches below
// the parent namespace and nothing above it.
type SecretsBackend interface {
	// EnsureNamespace makes child under parent; one already there is success.
	EnsureNamespace(ctx context.Context, parent, child string) error
	// DeleteNamespace deletes child and everything in it; absent is success.
	DeleteNamespace(ctx context.Context, parent, child string) error
	// EnableKV2 and EnableAppRole enable a mount; one already there is success.
	EnableKV2(ctx context.Context, ns, mount string) error
	EnableAppRole(ctx context.Context, ns, mount string) error
	PutPolicy(ctx context.Context, ns, name, policy string) error
	// DeletePolicy: absent is success.
	DeletePolicy(ctx context.Context, ns, name string) error
	PutAppRole(ctx context.Context, ns, mount, name string, r AppRole) error
	// DeleteAppRole: absent is success.
	DeleteAppRole(ctx context.Context, ns, mount, name string) error
	// RoleID returns ErrAbsent when there is no such role.
	RoleID(ctx context.Context, ns, mount, name string) (string, error)
	NewSecretID(ctx context.Context, ns, mount, name string) (string, error)
	WriteKV(ctx context.Context, ns, mount, path string, data map[string]string) error
	// KVVersion returns ErrAbsent when there is no such secret.
	KVVersion(ctx context.Context, ns, mount, path string) (int, error)
	// DeleteKV deletes every version; absent is success.
	DeleteKV(ctx context.Context, ns, mount, path string) error
}

// AppRole is a reader's role as OpenBao needs it.
type AppRole struct {
	TokenPolicies []string
	TokenTTL      string
	TokenMaxTTL   string
	// SecretIDTTL "0" and SecretIDNumUses 0 make the secret ID reusable and
	// lasting: the workload logs in again each time its service starts
	// (ADR-0021 §4).
	SecretIDTTL     string
	SecretIDNumUses int
	// BoundCIDRs binds both the secret ID and the tokens it gets to the
	// workload's address, so a copy used from anywhere else is refused.
	BoundCIDRs []string
}

// RuntimeSecret is a secret the tenant declared, as the registry holds it:
// its path and the tenant's own version, never its value.
type RuntimeSecret struct {
	Tenant string
	Path   string
	// Version is the tenant's, not OpenBao's. It is how the provider knows to
	// write again: a new value comes with a new version.
	Version   int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SecretReader is one workload's read access to some of its tenant's
// secrets, as the registry holds it.
type SecretReader struct {
	Tenant    string
	Name      string
	Workload  string
	Paths     []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// IssuedSecretReader is a reader with the credential the workload logs in
// with. SecretID is set only by PutSecretReader.
type IssuedSecretReader struct {
	SecretReader
	RoleID   string
	SecretID string
	// Namespace and Addr are where the workload logs in: tenants/<name> on
	// the site's OpenBao.
	Namespace string
	Addr      string
}

// ValidSecretPath reports whether p is a secret path a tenant may use: one
// to four segments of [a-z0-9_-]{1,64} joined by "/", at most 128 characters.
// Nothing else reaches OpenBao or a policy, so no path can name another mount
// or break out of the policy text.
func ValidSecretPath(p string) bool {
	if p == "" || len(p) > maxSecretPathLen {
		return false
	}
	segs := strings.Split(p, "/")
	if len(segs) > 4 {
		return false
	}
	for _, s := range segs {
		if !secretSegment.MatchString(s) {
			return false
		}
	}
	return true
}

// ValidReaderName reports whether n is a reader name: [a-z0-9-]{1,32}.
func ValidReaderName(n string) bool { return readerName.MatchString(n) }

// secretsNamespace is the tenant's namespace, tenants/<name>.
func (s *Service) secretsNamespace(name string) string {
	return s.SecretsNamespace + "/" + name
}

// ensureSecrets makes the tenant's namespace and its two mounts. Each call
// is an ensure, so a reconcile after the namespace was lost brings it back
// empty, and the tenant's next apply fills it.
func (s *Service) ensureSecrets(ctx context.Context, rec Record) error {
	if err := s.TenantSecrets.EnsureNamespace(ctx, s.SecretsNamespace, rec.Name); err != nil {
		return err
	}
	ns := s.secretsNamespace(rec.Name)
	if err := s.TenantSecrets.EnableKV2(ctx, ns, SecretsMount); err != nil {
		return err
	}
	return s.TenantSecrets.EnableAppRole(ctx, ns, AppRoleMount)
}

// removeSecrets deletes the tenant's namespace, and with it every secret,
// AppRole, policy and token in it.
func (s *Service) removeSecrets(ctx context.Context, rec Record) error {
	return s.TenantSecrets.DeleteNamespace(ctx, s.SecretsNamespace, rec.Name)
}

// secretsTenant checks the service is offered and the tenant can take
// secrets: registered and ready, so its namespace has been made.
func (s *Service) secretsTenant(ctx context.Context, tenantName string) error {
	if s.TenantSecrets == nil {
		return ErrSecretsNotOffered
	}
	rec, err := s.Store.Get(ctx, tenantName)
	if err != nil {
		return err
	}
	if rec.Status != StatusReady {
		return invalid("tenant %q is %s", tenantName, rec.Status)
	}
	return nil
}

// secretsStep wraps an OpenBao failure as the secrets step. A sealed or
// unreachable OpenBao stays ErrSecretsUnavailable underneath, which the
// server answers 503 rather than 502.
func secretsStep(err error) error {
	return &StepError{Step: StepSecrets, Err: err}
}

// PutRuntimeSecret writes a secret's value into the tenant's KV mount and
// records its path and version. The value goes to OpenBao and nowhere else:
// not the registry, not the audit log, not the response.
func (s *Service) PutRuntimeSecret(ctx context.Context, tenantName, path string, data map[string]string, version int) (RuntimeSecret, error) {
	if s.TenantSecrets == nil {
		return RuntimeSecret{}, ErrSecretsNotOffered
	}
	if !ValidSecretPath(path) {
		return RuntimeSecret{}, invalid("secret path must be 1-4 segments of [a-z0-9_-]{1,64} joined by /, at most %d characters", maxSecretPathLen)
	}
	if version < 1 {
		return RuntimeSecret{}, invalid("version must be 1 or more")
	}
	if len(data) == 0 {
		return RuntimeSecret{}, invalid("data must hold at least one key")
	}
	for k := range data {
		if k == "" {
			return RuntimeSecret{}, invalid("data keys cannot be empty")
		}
	}
	if err := s.secretsTenant(ctx, tenantName); err != nil {
		return RuntimeSecret{}, err
	}
	if err := s.TenantSecrets.WriteKV(ctx, s.secretsNamespace(tenantName), SecretsMount, path, data); err != nil {
		s.logger().Error("writing tenant secret", "tenant", tenantName, "path", path, "err", err)
		return RuntimeSecret{}, secretsStep(err)
	}
	sec, err := s.Store.PutRuntimeSecret(ctx, RuntimeSecret{Tenant: tenantName, Path: path, Version: version})
	if err != nil {
		return RuntimeSecret{}, err
	}
	s.audit(ctx, "secret-put", tenantName, map[string]any{"path": path, "version": version})
	return sec, nil
}

// GetRuntimeSecret reports a declared secret's version. It is ErrNotFound
// when the registry has no record of it, and also when OpenBao no longer
// holds it - after a rebuild - so the provider writes it again.
func (s *Service) GetRuntimeSecret(ctx context.Context, tenantName, path string) (RuntimeSecret, error) {
	if s.TenantSecrets == nil {
		return RuntimeSecret{}, ErrSecretsNotOffered
	}
	if !ValidSecretPath(path) {
		return RuntimeSecret{}, ErrNotFound
	}
	sec, err := s.Store.GetRuntimeSecret(ctx, tenantName, path)
	if err != nil {
		return RuntimeSecret{}, err
	}
	if _, err := s.TenantSecrets.KVVersion(ctx, s.secretsNamespace(tenantName), SecretsMount, path); err != nil {
		if errors.Is(err, ErrAbsent) {
			return RuntimeSecret{}, ErrNotFound
		}
		return RuntimeSecret{}, secretsStep(err)
	}
	return sec, nil
}

// DeleteRuntimeSecret deletes every version of the secret in OpenBao, then
// its record. One OpenBao already lost is deleted from the registry all the
// same. A reader naming it keeps a policy line for a path that holds nothing.
func (s *Service) DeleteRuntimeSecret(ctx context.Context, tenantName, path string) error {
	if s.TenantSecrets == nil {
		return ErrSecretsNotOffered
	}
	if !ValidSecretPath(path) {
		return ErrNotFound
	}
	if _, err := s.Store.GetRuntimeSecret(ctx, tenantName, path); err != nil {
		return err
	}
	if err := s.TenantSecrets.DeleteKV(ctx, s.secretsNamespace(tenantName), SecretsMount, path); err != nil {
		s.logger().Error("deleting tenant secret", "tenant", tenantName, "path", path, "err", err)
		return secretsStep(err)
	}
	s.audit(ctx, "secret-delete", tenantName, map[string]any{"path": path})
	return s.Store.DeleteRuntimeSecret(ctx, tenantName, path)
}

// readerPolicy grants read on exactly the paths named, and nothing else.
// The paths are validated, so none can close the string or the block.
func readerPolicy(paths []string) string {
	var b strings.Builder
	for _, p := range paths {
		fmt.Fprintf(&b, "path %q {\n  capabilities = [\"read\"]\n}\n", SecretsMount+"/data/"+p)
	}
	return b.String()
}

// PutSecretReader gives one of the tenant's workloads read access to the
// paths named, and returns the credential it logs in with.
//
// Every call issues a new credential: the old AppRole is deleted first, so
// every secret ID issued before stops logging in, and the provider holds the
// one returned here. The registry row is written last, so a reader the
// registry holds always has its role.
func (s *Service) PutSecretReader(ctx context.Context, tenantName, name, workload string, paths []string) (IssuedSecretReader, error) {
	if s.TenantSecrets == nil {
		return IssuedSecretReader{}, ErrSecretsNotOffered
	}
	if !ValidReaderName(name) {
		return IssuedSecretReader{}, invalid("reader name must be 1-32 lowercase alphanumerics or dashes")
	}
	if len(paths) == 0 || len(paths) > maxReaderPaths {
		return IssuedSecretReader{}, invalid("a reader names 1-%d paths", maxReaderPaths)
	}
	var uniq []string
	seen := map[string]bool{}
	for _, p := range paths {
		if !ValidSecretPath(p) {
			return IssuedSecretReader{}, invalid("path %q must be 1-4 segments of [a-z0-9_-]{1,64} joined by /, at most %d characters", p, maxSecretPathLen)
		}
		if !seen[p] {
			seen[p] = true
			uniq = append(uniq, p)
		}
	}
	if err := s.secretsTenant(ctx, tenantName); err != nil {
		return IssuedSecretReader{}, err
	}
	for _, p := range uniq {
		if _, err := s.Store.GetRuntimeSecret(ctx, tenantName, p); errors.Is(err, ErrNotFound) {
			return IssuedSecretReader{}, invalid("secret %q is not declared by this tenant", p)
		} else if err != nil {
			return IssuedSecretReader{}, err
		}
	}
	w, err := s.Store.GetWorkload(ctx, tenantName, workload)
	if errors.Is(err, ErrNotFound) {
		return IssuedSecretReader{}, invalid("workload %q is not one of this tenant's", workload)
	}
	if err != nil {
		return IssuedSecretReader{}, err
	}
	if w.Address == "" {
		return IssuedSecretReader{}, invalid("workload %q has no address yet", workload)
	}

	ns := s.secretsNamespace(tenantName)
	policy := readerPolicyPrefix + name
	var roleID, secretID string
	err = func() error {
		// The old role first, so no secret ID issued before survives.
		if err := s.TenantSecrets.DeleteAppRole(ctx, ns, AppRoleMount, name); err != nil {
			return err
		}
		if err := s.TenantSecrets.PutPolicy(ctx, ns, policy, readerPolicy(uniq)); err != nil {
			return err
		}
		if err := s.TenantSecrets.PutAppRole(ctx, ns, AppRoleMount, name, AppRole{
			TokenPolicies:   []string{policy},
			TokenTTL:        "1h",
			TokenMaxTTL:     "24h",
			SecretIDTTL:     "0",
			SecretIDNumUses: 0,
			BoundCIDRs:      []string{w.Address + "/32"},
		}); err != nil {
			return err
		}
		var err error
		if roleID, err = s.TenantSecrets.RoleID(ctx, ns, AppRoleMount, name); err != nil {
			return err
		}
		secretID, err = s.TenantSecrets.NewSecretID(ctx, ns, AppRoleMount, name)
		return err
	}()
	if err != nil {
		s.logger().Error("writing secret reader", "tenant", tenantName, "reader", name, "err", err)
		return IssuedSecretReader{}, secretsStep(err)
	}
	r, err := s.Store.PutSecretReader(ctx, SecretReader{Tenant: tenantName, Name: name, Workload: workload, Paths: uniq})
	if err != nil {
		return IssuedSecretReader{}, err
	}
	s.audit(ctx, "secret-reader-put", tenantName, map[string]any{"reader": name, "workload": workload, "paths": uniq})
	return IssuedSecretReader{SecretReader: r, RoleID: roleID, SecretID: secretID, Namespace: ns, Addr: s.SecretsAddr}, nil
}

// GetSecretReader returns a reader without its secret ID, which the API does
// not keep. It is ErrNotFound when the registry has no record of it, and
// also when OpenBao no longer holds its role, so the provider issues it
// again.
func (s *Service) GetSecretReader(ctx context.Context, tenantName, name string) (IssuedSecretReader, error) {
	if s.TenantSecrets == nil {
		return IssuedSecretReader{}, ErrSecretsNotOffered
	}
	r, err := s.Store.GetSecretReader(ctx, tenantName, name)
	if err != nil {
		return IssuedSecretReader{}, err
	}
	ns := s.secretsNamespace(tenantName)
	roleID, err := s.TenantSecrets.RoleID(ctx, ns, AppRoleMount, name)
	if errors.Is(err, ErrAbsent) {
		return IssuedSecretReader{}, ErrNotFound
	}
	if err != nil {
		return IssuedSecretReader{}, secretsStep(err)
	}
	return IssuedSecretReader{SecretReader: r, RoleID: roleID, Namespace: ns, Addr: s.SecretsAddr}, nil
}

// DeleteSecretReader revokes a reader: its AppRole, so it cannot log in
// again, and its policy, so a token it already holds reads nothing more.
func (s *Service) DeleteSecretReader(ctx context.Context, tenantName, name string) error {
	if s.TenantSecrets == nil {
		return ErrSecretsNotOffered
	}
	r, err := s.Store.GetSecretReader(ctx, tenantName, name)
	if err != nil {
		return err
	}
	return s.removeReader(ctx, r)
}

func (s *Service) removeReader(ctx context.Context, r SecretReader) error {
	if s.TenantSecrets != nil {
		ns := s.secretsNamespace(r.Tenant)
		if err := s.TenantSecrets.DeleteAppRole(ctx, ns, AppRoleMount, r.Name); err != nil {
			return secretsStep(err)
		}
		if err := s.TenantSecrets.DeletePolicy(ctx, ns, readerPolicyPrefix+r.Name); err != nil {
			return secretsStep(err)
		}
	}
	s.audit(ctx, "secret-reader-delete", r.Tenant, map[string]any{"reader": r.Name, "workload": r.Workload})
	return s.Store.DeleteSecretReader(ctx, r.Tenant, r.Name)
}

// removeWorkloadReaders revokes every reader of a workload being destroyed
// (ADR-0021 §5). At a site that no longer offers the service, the rows go
// and there is nothing in OpenBao to revoke.
func (s *Service) removeWorkloadReaders(ctx context.Context, tenantName, workload string) error {
	readers, err := s.Store.ListSecretReaders(ctx, tenantName)
	if err != nil {
		return err
	}
	for _, r := range readers {
		if r.Workload != workload {
			continue
		}
		if err := s.removeReader(ctx, r); err != nil {
			return err
		}
	}
	return nil
}
