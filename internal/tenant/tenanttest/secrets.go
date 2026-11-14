package tenanttest

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// The registry's runtime secret and reader rows.

func (s *Store) PutRuntimeSecret(_ context.Context, sec tenant.RuntimeSecret) (tenant.RuntimeSecret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[sec.Tenant]; !ok {
		return tenant.RuntimeSecret{}, tenant.ErrNotFound
	}
	if s.runtimeSecrets == nil {
		s.runtimeSecrets = map[string]tenant.RuntimeSecret{}
	}
	key := sec.Tenant + "/" + sec.Path
	if old, ok := s.runtimeSecrets[key]; ok {
		sec.CreatedAt = old.CreatedAt
	} else {
		sec.CreatedAt = time.Now()
	}
	sec.UpdatedAt = time.Now()
	s.runtimeSecrets[key] = sec
	return sec, nil
}

func (s *Store) GetRuntimeSecret(_ context.Context, tenantName, path string) (tenant.RuntimeSecret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.runtimeSecrets[tenantName+"/"+path]
	if !ok {
		return tenant.RuntimeSecret{}, tenant.ErrNotFound
	}
	return sec, nil
}

func (s *Store) DeleteRuntimeSecret(_ context.Context, tenantName, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.runtimeSecrets, tenantName+"/"+path)
	return nil
}

func (s *Store) PutSecretReader(_ context.Context, r tenant.SecretReader) (tenant.SecretReader, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[r.Tenant]; !ok {
		return tenant.SecretReader{}, tenant.ErrNotFound
	}
	if s.secretReaders == nil {
		s.secretReaders = map[string]tenant.SecretReader{}
	}
	key := r.Tenant + "/" + r.Name
	if old, ok := s.secretReaders[key]; ok {
		r.CreatedAt = old.CreatedAt
	} else {
		r.CreatedAt = time.Now()
	}
	r.UpdatedAt = time.Now()
	r.Paths = append([]string(nil), r.Paths...)
	s.secretReaders[key] = r
	return r, nil
}

func (s *Store) GetSecretReader(_ context.Context, tenantName, name string) (tenant.SecretReader, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.secretReaders[tenantName+"/"+name]
	if !ok {
		return tenant.SecretReader{}, tenant.ErrNotFound
	}
	return r, nil
}

func (s *Store) ListSecretReaders(_ context.Context, tenantName string) ([]tenant.SecretReader, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []tenant.SecretReader
	for _, r := range s.secretReaders {
		if r.Tenant == tenantName {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) DeleteSecretReader(_ context.Context, tenantName, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.secretReaders, tenantName+"/"+name)
	return nil
}

// Bao is an in-memory OpenBao holding tenants' namespaces. Everything is
// keyed by the full namespace, "tenants/eds", as OpenBao addresses it.
type Bao struct {
	mu sync.Mutex
	// Namespaces holds each namespace's mounts, by path: "secrets" -> "kv-v2".
	Namespaces map[string]map[string]string
	// KV is "<ns>/<path>" -> the data written last, and Versions its version.
	KV       map[string]map[string]string
	Versions map[string]int
	// Policies is "<ns>/<name>" -> policy text.
	Policies map[string]string
	// Roles is "<ns>/<name>" -> the AppRole; RoleIDs and SecretIDs what was
	// issued for each. A role deleted takes its secret IDs with it.
	Roles     map[string]tenant.AppRole
	RoleIDs   map[string]string
	SecretIDs map[string][]string
	// Calls is every call made, "<method> <ns> <what>", in order.
	Calls []string
	// Err, when set, fails every call.
	Err  error
	next int
}

func NewBao() *Bao {
	return &Bao{
		Namespaces: map[string]map[string]string{},
		KV:         map[string]map[string]string{},
		Versions:   map[string]int{},
		Policies:   map[string]string{},
		Roles:      map[string]tenant.AppRole{},
		RoleIDs:    map[string]string{},
		SecretIDs:  map[string][]string{},
	}
}

// begin records a call, under the lock the caller holds.
func (b *Bao) begin(call string) error {
	b.Calls = append(b.Calls, call)
	return b.Err
}

func dropPrefix[V any](m map[string]V, prefix string) {
	for k := range m {
		if strings.HasPrefix(k, prefix) {
			delete(m, k)
		}
	}
}

func (b *Bao) EnsureNamespace(_ context.Context, parent, child string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin("ensure-namespace " + parent + " " + child); err != nil {
		return err
	}
	if _, ok := b.Namespaces[parent+"/"+child]; !ok {
		b.Namespaces[parent+"/"+child] = map[string]string{}
	}
	return nil
}

// DeleteNamespace drops everything under it, as OpenBao does.
func (b *Bao) DeleteNamespace(_ context.Context, parent, child string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin("delete-namespace " + parent + " " + child); err != nil {
		return err
	}
	ns := parent + "/" + child
	delete(b.Namespaces, ns)
	dropPrefix(b.KV, ns+"/")
	dropPrefix(b.Versions, ns+"/")
	dropPrefix(b.Policies, ns+"/")
	dropPrefix(b.Roles, ns+"/")
	dropPrefix(b.RoleIDs, ns+"/")
	dropPrefix(b.SecretIDs, ns+"/")
	return nil
}

func (b *Bao) enable(ns, mount, typ string) error {
	mounts, ok := b.Namespaces[ns]
	if !ok {
		return fmt.Errorf("namespace %s does not exist", ns)
	}
	// Already there is success, as the client reads "path is already in use".
	mounts[mount] = typ
	return nil
}

func (b *Bao) EnableKV2(_ context.Context, ns, mount string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin("enable-kv " + ns + " " + mount); err != nil {
		return err
	}
	return b.enable(ns, mount, "kv-v2")
}

func (b *Bao) EnableAppRole(_ context.Context, ns, mount string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin("enable-approle " + ns + " " + mount); err != nil {
		return err
	}
	return b.enable(ns, mount, "approle")
}

func (b *Bao) PutPolicy(_ context.Context, ns, name, policy string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin("put-policy " + ns + " " + name); err != nil {
		return err
	}
	b.Policies[ns+"/"+name] = policy
	return nil
}

func (b *Bao) DeletePolicy(_ context.Context, ns, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin("delete-policy " + ns + " " + name); err != nil {
		return err
	}
	delete(b.Policies, ns+"/"+name)
	return nil
}

func (b *Bao) PutAppRole(_ context.Context, ns, _, name string, r tenant.AppRole) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin("put-approle " + ns + " " + name); err != nil {
		return err
	}
	key := ns + "/" + name
	b.Roles[key] = r
	if b.RoleIDs[key] == "" {
		b.next++
		b.RoleIDs[key] = fmt.Sprintf("role-id-%d", b.next)
	}
	return nil
}

func (b *Bao) DeleteAppRole(_ context.Context, ns, _, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin("delete-approle " + ns + " " + name); err != nil {
		return err
	}
	key := ns + "/" + name
	delete(b.Roles, key)
	delete(b.RoleIDs, key)
	delete(b.SecretIDs, key)
	return nil
}

func (b *Bao) RoleID(_ context.Context, ns, _, name string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin("role-id " + ns + " " + name); err != nil {
		return "", err
	}
	id, ok := b.RoleIDs[ns+"/"+name]
	if !ok {
		return "", tenant.ErrAbsent
	}
	return id, nil
}

func (b *Bao) NewSecretID(_ context.Context, ns, _, name string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin("secret-id " + ns + " " + name); err != nil {
		return "", err
	}
	key := ns + "/" + name
	if _, ok := b.Roles[key]; !ok {
		return "", fmt.Errorf("role %s does not exist", key)
	}
	b.next++
	id := fmt.Sprintf("secret-id-%d", b.next)
	b.SecretIDs[key] = append(b.SecretIDs[key], id)
	return id, nil
}

func (b *Bao) WriteKV(_ context.Context, ns, mount, path string, data map[string]string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin("write-kv " + ns + " " + path); err != nil {
		return err
	}
	if b.Namespaces[ns][mount] != "kv-v2" {
		return fmt.Errorf("no KV mount %s in %s", mount, ns)
	}
	key := ns + "/" + path
	cp := map[string]string{}
	for k, v := range data {
		cp[k] = v
	}
	b.KV[key] = cp
	b.Versions[key]++
	return nil
}

func (b *Bao) KVVersion(_ context.Context, ns, _, path string) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin("kv-version " + ns + " " + path); err != nil {
		return 0, err
	}
	v, ok := b.Versions[ns+"/"+path]
	if !ok {
		return 0, tenant.ErrAbsent
	}
	return v, nil
}

func (b *Bao) DeleteKV(_ context.Context, ns, _, path string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin("delete-kv " + ns + " " + path); err != nil {
		return err
	}
	delete(b.KV, ns+"/"+path)
	delete(b.Versions, ns+"/"+path)
	return nil
}
