package minio

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

func TestPolicyMatchesTheMinioRole(t *testing.T) {
	raw, err := Policy("tf-state", "tenants/eds/")
	if err != nil {
		t.Fatal(err)
	}
	// The statement the deevnet.mgmt minio role writes, so existing tenants are
	// adopted without a change in what they may do.
	const role = `{
	  "Version": "2012-10-17",
	  "Statement": [
	    {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::tf-state"],
	     "Condition": {"StringLike": {"s3:prefix": ["tenants/eds/*"]}}},
	    {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
	     "Resource": ["arn:aws:s3:::tf-state/tenants/eds/*"]}
	  ]
	}`
	var got, want any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(role), &want); err != nil {
		t.Fatal(err)
	}
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if string(g) != string(w) {
		t.Fatalf("policy\n got %s\nwant %s", g, w)
	}
}

// Needs a MinIO the test may write to: DEEVNET_TEST_MINIO_ENDPOINT (host:port),
// DEEVNET_TEST_MINIO_ACCESS_KEY and DEEVNET_TEST_MINIO_SECRET_KEY, ideally the
// scoped admin user the deevnet_api role creates.
func TestEnsureAndRemove(t *testing.T) {
	ep := os.Getenv("DEEVNET_TEST_MINIO_ENDPOINT")
	if ep == "" {
		t.Skip("DEEVNET_TEST_MINIO_ENDPOINT not set")
	}
	c, err := New(ep, os.Getenv("DEEVNET_TEST_MINIO_ACCESS_KEY"), os.Getenv("DEEVNET_TEST_MINIO_SECRET_KEY"), false)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st := tenant.StateTenant{User: "tprobe", Secret: "first-secret-1234", Bucket: "tf-state", Prefix: "tenants/tprobe/"}
	t.Cleanup(func() { _ = c.Remove(context.Background(), st.User) })

	if err := c.Ensure(ctx, st); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := c.Ensure(ctx, st); err != nil {
		t.Fatalf("ensure again: %v", err)
	}
	// A restore with another secret replaces it and keeps the policy attached.
	st.Secret = "second-secret-5678"
	if err := c.Ensure(ctx, st); err != nil {
		t.Fatalf("ensure rotated: %v", err)
	}
	info, err := c.admin.GetUserInfo(ctx, st.User)
	if err != nil || info.PolicyName != PolicyName(st.User) {
		t.Fatalf("user info %+v (%v), want policy %s attached", info.PolicyName, err, PolicyName(st.User))
	}

	if err := c.Remove(ctx, st.User); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := c.Remove(ctx, st.User); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}
