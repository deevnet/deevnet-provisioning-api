// Package minio ensures a tenant's state-store user and the policy that confines
// it to its own prefix (ADR-0007), through the MinIO admin API.
//
// Behaviour relied on here was checked against RELEASE.2025-09-07T16-13-09Z:
//   - adding an existing user replaces its secret
//   - adding an existing canned policy replaces it
//   - re-attaching an attached policy answers XMinioAdminPolicyChangeAlreadyApplied
//   - a user whose policy grants only the admin actions in the deevnet_api role
//     can do all of the above
//   - with the S3 statement the minio role adds for it, the same user can list
//     and delete every version under tenants/, and nothing outside it (Purge)
package minio

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/minio/madmin-go/v3"
	miniogo "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Client is a tenant.StateStore.
type Client struct {
	admin *madmin.AdminClient
	// s3 deletes a removed tenant's state objects (Purge), with the same
	// credential and connection settings as admin.
	s3 *miniogo.Client
}

// New takes host:port, for example 10.20.25.20:9000, and the API's own admin
// credential, never the root one.
//
// With useTLS, caFile is the site CA the state store's certificate must verify
// against (CHG-0030). It is required: this client never skips verification,
// because what crosses this connection is the admin credential that creates
// every tenant's state-store user.
func New(endpoint, accessKey, secretKey string, useTLS bool, caFile string) (*Client, error) {
	opts := &madmin.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useTLS,
	}
	if useTLS {
		if caFile == "" {
			return nil, errors.New("TLS needs a CA file; this client does not skip verification")
		}
		raw, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("state store CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("state store CA %s holds no certificate", caFile)
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		opts.Transport = tr
	}
	a, err := madmin.NewWithOptions(endpoint, opts)
	if err != nil {
		return nil, err
	}
	s3, err := miniogo.New(endpoint, &miniogo.Options{Creds: opts.Creds, Secure: opts.Secure, Transport: opts.Transport})
	if err != nil {
		return nil, err
	}
	return &Client{admin: a, s3: s3}, nil
}

// PolicyName is the canned policy that confines one tenant, the same name the
// minio role has always used, so existing tenants are adopted in place.
func PolicyName(user string) string { return "tenant-" + user }

// Policy is the tenant's prefix confinement: list its prefix, read and write
// objects under it, nothing else. It matches the minio role's policy statement
// for statement.
func Policy(bucket, prefix string) ([]byte, error) {
	type condition struct {
		StringLike map[string][]string `json:"StringLike"`
	}
	type statement struct {
		Effect    string     `json:"Effect"`
		Action    []string   `json:"Action"`
		Resource  []string   `json:"Resource"`
		Condition *condition `json:"Condition,omitempty"`
	}
	doc := struct {
		Version   string      `json:"Version"`
		Statement []statement `json:"Statement"`
	}{
		Version: "2012-10-17",
		Statement: []statement{
			{
				Effect:    "Allow",
				Action:    []string{"s3:ListBucket"},
				Resource:  []string{"arn:aws:s3:::" + bucket},
				Condition: &condition{StringLike: map[string][]string{"s3:prefix": {prefix + "*"}}},
			},
			{
				Effect:   "Allow",
				Action:   []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"},
				Resource: []string{"arn:aws:s3:::" + bucket + "/" + prefix + "*"},
			},
		},
	}
	return json.Marshal(doc)
}

func (c *Client) Ensure(ctx context.Context, t tenant.StateTenant) error {
	pol, err := Policy(t.Bucket, t.Prefix)
	if err != nil {
		return err
	}
	if err := c.admin.AddCannedPolicy(ctx, PolicyName(t.User), pol); err != nil {
		return fmt.Errorf("policy %s: %w", PolicyName(t.User), err)
	}
	if err := c.admin.AddUser(ctx, t.User, t.Secret); err != nil {
		return fmt.Errorf("user %s: %w", t.User, err)
	}
	_, err = c.admin.AttachPolicy(ctx, madmin.PolicyAssociationReq{Policies: []string{PolicyName(t.User)}, User: t.User})
	if err != nil && !hasCode(err, "XMinioAdminPolicyChangeAlreadyApplied") {
		return fmt.Errorf("attach %s to %s: %w", PolicyName(t.User), t.User, err)
	}
	return nil
}

// Remove deletes the user and its policy. The tenant's state objects are left
// in the bucket: they are the tenant's, and versioning keeps them either way.
func (c *Client) Remove(ctx context.Context, user string) error {
	if err := c.admin.RemoveUser(ctx, user); err != nil && !hasCode(err, "XMinioAdminNoSuchUser") {
		return fmt.Errorf("remove user %s: %w", user, err)
	}
	if err := c.admin.RemoveCannedPolicy(ctx, PolicyName(user)); err != nil && !hasCode(err, "XMinioAdminNoSuchPolicy") {
		return fmt.Errorf("remove policy %s: %w", PolicyName(user), err)
	}
	return nil
}

// Purge deletes every version of every object under a removed tenant's
// prefix, and every delete marker, so nothing of its state is left in the
// versioned bucket (CHG-0065). A plain delete would only add delete markers,
// with every earlier state, credentials and all, kept underneath them.
//
// The prefix must be a tenant's: "tenants/<name>/". Anything else is refused
// here, as it is by the API user's policy on the store, because an empty or
// shorter prefix would reach other tenants' state or the fabric's.
func (c *Client) Purge(ctx context.Context, bucket, prefix string) error {
	name, ok := strings.CutPrefix(prefix, "tenants/")
	if !ok || !strings.HasSuffix(name, "/") || !tenant.ValidName(strings.TrimSuffix(name, "/")) {
		return fmt.Errorf("refusing to purge %q: not a tenant's state prefix", prefix)
	}
	listCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	found := c.s3.ListObjects(listCtx, bucket, miniogo.ListObjectsOptions{Prefix: prefix, Recursive: true, WithVersions: true})
	toDelete := make(chan miniogo.ObjectInfo)
	var listErr error
	go func() {
		defer close(toDelete)
		for o := range found {
			if o.Err != nil {
				listErr = o.Err
				cancel()
				return
			}
			select {
			case toDelete <- o:
			case <-listCtx.Done():
				return
			}
		}
	}()
	for e := range c.s3.RemoveObjects(ctx, bucket, toDelete, miniogo.RemoveObjectsOptions{}) {
		if e.Err != nil {
			cancel()
			for range toDelete {
			}
			return fmt.Errorf("delete %s version %s: %w", e.ObjectName, e.VersionID, e.Err)
		}
	}
	if listErr != nil {
		return fmt.Errorf("list versions under %s: %w", prefix, listErr)
	}
	// What a purge is for is "nothing left", so that is what it checks.
	for o := range c.s3.ListObjects(ctx, bucket, miniogo.ListObjectsOptions{Prefix: prefix, Recursive: true, WithVersions: true, MaxKeys: 1}) {
		if o.Err != nil {
			return fmt.Errorf("list versions under %s: %w", prefix, o.Err)
		}
		return fmt.Errorf("purge left %s version %s under %s", o.Key, o.VersionID, prefix)
	}
	return nil
}

func hasCode(err error, code string) bool {
	var er madmin.ErrorResponse
	return errors.As(err, &er) && er.Code == code
}
