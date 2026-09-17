// Package minio ensures a tenant's state-store user and the policy that confines
// it to its own prefix (ADR-0007), through the MinIO admin API.
//
// Behaviour relied on here was checked against RELEASE.2025-09-07T16-13-09Z:
//   - adding an existing user replaces its secret
//   - adding an existing canned policy replaces it
//   - re-attaching an attached policy answers XMinioAdminPolicyChangeAlreadyApplied
//   - a user whose policy grants only the admin actions in the deevnet_api role
//     can do all of the above
package minio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/minio/madmin-go/v3"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Client is a tenant.StateStore.
type Client struct {
	admin *madmin.AdminClient
}

// New takes host:port, for example 10.20.25.20:9000, and the API's own admin
// credential, never the root one.
func New(endpoint, accessKey, secretKey string, useTLS bool) (*Client, error) {
	a, err := madmin.New(endpoint, accessKey, secretKey, useTLS)
	if err != nil {
		return nil, err
	}
	return &Client{admin: a}, nil
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

func hasCode(err error, code string) bool {
	var er madmin.ErrorResponse
	return errors.As(err, &er) && er.Code == code
}
