package openbao

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Tenants' own namespaces (ADR-0021, CHG-0067).
//
// Every call here carries X-Vault-Namespace, and the API's policy grants what
// these calls need below the parent namespace and nothing above it: namespace
// administration at tenants/sys/namespaces/*, and inside each tenant's
// namespace its mounts, its AppRoles, its policies, and on its KV mount
// create and update on data/ with read and delete on metadata/. Never read on
// data/: the API writes a tenant's secret and cannot read it back.
//
// The listing endpoints (sys/mounts, sys/auth) are not granted either, so an
// enable is made idempotent by trying it and reading OpenBao's "path is
// already in use" refusal as success, rather than by reading first.
//
// The paths and answers were checked against OpenBao 2.6.2 on 2026-11-14.

const namespaceHeader = "X-Vault-Namespace"

// ErrAbsent is a namespace, secret or AppRole OpenBao does not hold.
var ErrAbsent = tenant.ErrAbsent

var _ tenant.SecretsBackend = (*Client)(nil)

// in calls OpenBao in namespace ns.
func (c *Client) in(ctx context.Context, ns, method, path string, body, out any) error {
	return c.doWith(ctx, map[string]string{namespaceHeader: ns}, method, path, body, out)
}

// statusIs reports whether err is OpenBao answering code.
func statusIs(err error, code int) bool {
	var se *statusError
	return errors.As(err, &se) && se.code == code
}

// absentOK makes a 404 success: what a delete of something already gone
// gets.
func absentOK(err error) error {
	if statusIs(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// escapePath escapes each segment of a path the caller has already
// validated, so nothing in it can change which endpoint is called.
func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// EnsureNamespace makes child under parent, unless it is already there.
func (c *Client) EnsureNamespace(ctx context.Context, parent, child string) error {
	path := "/v1/sys/namespaces/" + url.PathEscape(child)
	err := c.in(ctx, parent, http.MethodGet, path, nil, nil)
	switch {
	case err == nil:
		return nil
	case !statusIs(err, http.StatusNotFound):
		return fmt.Errorf("openbao: namespace %s/%s: %w", parent, child, err)
	}
	if err := c.in(ctx, parent, http.MethodPost, path, map[string]any{}, nil); err != nil {
		return fmt.Errorf("openbao: creating namespace %s/%s: %w", parent, child, err)
	}
	return nil
}

// DeleteNamespace deletes child and everything in it: its mounts, AppRoles,
// policies and tokens. OpenBao answers "in-progress" and finishes on its
// own. A namespace that is not there is not an error.
func (c *Client) DeleteNamespace(ctx context.Context, parent, child string) error {
	err := c.in(ctx, parent, http.MethodDelete, "/v1/sys/namespaces/"+url.PathEscape(child), nil, nil)
	if err := absentOK(err); err != nil {
		return fmt.Errorf("openbao: deleting namespace %s/%s: %w", parent, child, err)
	}
	return nil
}

// alreadyInUse is OpenBao refusing to enable a mount where one is: a 400
// saying "path is already in use".
func alreadyInUse(err error) bool {
	var se *statusError
	return errors.As(err, &se) && se.code == http.StatusBadRequest && strings.Contains(se.body, "already in use")
}

// EnableKV2 enables a KV version 2 secrets engine at mount in ns. One already
// there is success.
func (c *Client) EnableKV2(ctx context.Context, ns, mount string) error {
	in := map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}
	err := c.in(ctx, ns, http.MethodPost, "/v1/sys/mounts/"+url.PathEscape(mount), in, nil)
	if err != nil && !alreadyInUse(err) {
		return fmt.Errorf("openbao: enabling KV at %s/%s: %w", ns, mount, err)
	}
	return nil
}

// EnableAppRole enables the AppRole auth method at mount in ns. One already
// there is success.
func (c *Client) EnableAppRole(ctx context.Context, ns, mount string) error {
	err := c.in(ctx, ns, http.MethodPost, "/v1/sys/auth/"+url.PathEscape(mount), map[string]string{"type": "approle"}, nil)
	if err != nil && !alreadyInUse(err) {
		return fmt.Errorf("openbao: enabling AppRole at %s/%s: %w", ns, mount, err)
	}
	return nil
}

// PutPolicy writes the ACL policy name in ns, replacing one that is there.
func (c *Client) PutPolicy(ctx context.Context, ns, name, policy string) error {
	err := c.in(ctx, ns, http.MethodPut, "/v1/sys/policies/acl/"+url.PathEscape(name), map[string]string{"policy": policy}, nil)
	if err != nil {
		return fmt.Errorf("openbao: policy %s in %s: %w", name, ns, err)
	}
	return nil
}

// DeletePolicy deletes the ACL policy name in ns. A token that carries it
// loses what it granted at its next request. One that is not there is not an
// error.
func (c *Client) DeletePolicy(ctx context.Context, ns, name string) error {
	if err := absentOK(c.in(ctx, ns, http.MethodDelete, "/v1/sys/policies/acl/"+url.PathEscape(name), nil, nil)); err != nil {
		return fmt.Errorf("openbao: deleting policy %s in %s: %w", name, ns, err)
	}
	return nil
}

func rolePath(mount, name string) string {
	return "/v1/auth/" + url.PathEscape(mount) + "/role/" + url.PathEscape(name)
}

// PutAppRole writes the AppRole name on the AppRole mount in ns, replacing
// its settings if it is there.
func (c *Client) PutAppRole(ctx context.Context, ns, mount, name string, r tenant.AppRole) error {
	in := map[string]any{
		"token_policies":        r.TokenPolicies,
		"token_ttl":             r.TokenTTL,
		"token_max_ttl":         r.TokenMaxTTL,
		"secret_id_ttl":         r.SecretIDTTL,
		"secret_id_num_uses":    r.SecretIDNumUses,
		"secret_id_bound_cidrs": r.BoundCIDRs,
		"token_bound_cidrs":     r.BoundCIDRs,
	}
	if err := c.in(ctx, ns, http.MethodPost, rolePath(mount, name), in, nil); err != nil {
		return fmt.Errorf("openbao: AppRole %s in %s: %w", name, ns, err)
	}
	return nil
}

// DeleteAppRole deletes the AppRole name and every secret ID issued for it.
// A token already issued keeps working until it expires or its policy goes.
// One that is not there is not an error.
func (c *Client) DeleteAppRole(ctx context.Context, ns, mount, name string) error {
	if err := absentOK(c.in(ctx, ns, http.MethodDelete, rolePath(mount, name), nil, nil)); err != nil {
		return fmt.Errorf("openbao: deleting AppRole %s in %s: %w", name, ns, err)
	}
	return nil
}

// RoleID returns the AppRole's role ID, which is not a secret, or ErrAbsent
// when OpenBao holds no such role.
func (c *Client) RoleID(ctx context.Context, ns, mount, name string) (string, error) {
	var out struct {
		Data struct {
			RoleID string `json:"role_id"`
		} `json:"data"`
	}
	err := c.in(ctx, ns, http.MethodGet, rolePath(mount, name)+"/role-id", nil, &out)
	switch {
	case statusIs(err, http.StatusNotFound):
		return "", ErrAbsent
	case err != nil:
		return "", fmt.Errorf("openbao: role ID of %s in %s: %w", name, ns, err)
	case out.Data.RoleID == "":
		return "", ErrAbsent
	}
	return out.Data.RoleID, nil
}

// NewSecretID issues a secret ID for the AppRole. It is returned once and not
// kept here.
func (c *Client) NewSecretID(ctx context.Context, ns, mount, name string) (string, error) {
	var out struct {
		Data struct {
			SecretID string `json:"secret_id"`
		} `json:"data"`
	}
	if err := c.in(ctx, ns, http.MethodPost, rolePath(mount, name)+"/secret-id", map[string]any{}, &out); err != nil {
		return "", fmt.Errorf("openbao: secret ID for %s in %s: %w", name, ns, err)
	}
	if out.Data.SecretID == "" {
		return "", errors.New("openbao: secret ID request returned none")
	}
	return out.Data.SecretID, nil
}

// WriteKV writes a new version of the KV v2 secret at path. Nothing is read
// back: the API's policy has no read on data/.
func (c *Client) WriteKV(ctx context.Context, ns, mount, path string, data map[string]string) error {
	err := c.in(ctx, ns, http.MethodPost, "/v1/"+url.PathEscape(mount)+"/data/"+escapePath(path),
		map[string]any{"data": data}, nil)
	if err != nil {
		// The path is the tenant's own name for it and not secret; the error
		// body is OpenBao's and never echoes the value.
		return fmt.Errorf("openbao: writing %s in %s: %w", path, ns, err)
	}
	return nil
}

// KVVersion returns the current version of the KV v2 secret at path from its
// metadata, or ErrAbsent when there is none: after an OpenBao rebuild, or a
// namespace deleted by hand.
func (c *Client) KVVersion(ctx context.Context, ns, mount, path string) (int, error) {
	var out struct {
		Data struct {
			CurrentVersion int `json:"current_version"`
		} `json:"data"`
	}
	err := c.in(ctx, ns, http.MethodGet, "/v1/"+url.PathEscape(mount)+"/metadata/"+escapePath(path), nil, &out)
	switch {
	case statusIs(err, http.StatusNotFound):
		return 0, ErrAbsent
	case err != nil:
		return 0, fmt.Errorf("openbao: metadata of %s in %s: %w", path, ns, err)
	case out.Data.CurrentVersion == 0:
		return 0, ErrAbsent
	}
	return out.Data.CurrentVersion, nil
}

// DeleteKV deletes the KV v2 secret at path, every version and its metadata.
// One that is not there is not an error.
func (c *Client) DeleteKV(ctx context.Context, ns, mount, path string) error {
	err := c.in(ctx, ns, http.MethodDelete, "/v1/"+url.PathEscape(mount)+"/metadata/"+escapePath(path), nil, nil)
	if err := absentOK(err); err != nil {
		return fmt.Errorf("openbao: deleting %s in %s: %w", path, ns, err)
	}
	return nil
}
