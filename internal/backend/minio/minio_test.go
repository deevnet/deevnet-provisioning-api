package minio

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/minio/madmin-go/v3"
	miniogo "github.com/minio/minio-go/v7"
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
	c, err := New(ep, os.Getenv("DEEVNET_TEST_MINIO_ACCESS_KEY"), os.Getenv("DEEVNET_TEST_MINIO_SECRET_KEY"), false, "")
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
	// And the old secret stops working, which is what a state-secret reissue
	// relies on (CHG-0060). Any user may read its own account.
	login := func(secret string) error {
		u, err := New(ep, st.User, secret, false, "")
		if err != nil {
			return err
		}
		_, err = u.admin.AccountInfo(ctx, madmin.AccountOpts{})
		return err
	}
	if err := login("second-secret-5678"); err != nil {
		t.Errorf("the new secret can't sign in: %v", err)
	}
	if err := login("first-secret-1234"); err == nil {
		t.Error("the old secret still signs in after a new one was ensured")
	}

	if err := c.Remove(ctx, st.User); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := c.Remove(ctx, st.User); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}

// apiAdminPolicy is the policy the deevnet.mgmt minio role gives the API's
// own user (provision_api_admin.yml): user and policy administration, and
// purging state under tenants/ only. Purge is tested as a user holding this,
// not as root, so a missing action fails here rather than in a live delete.
const apiAdminPolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["admin:CreateUser", "admin:DeleteUser", "admin:GetUser", "admin:ListUsers",
      "admin:CreatePolicy", "admin:DeletePolicy", "admin:GetPolicy", "admin:AttachUserOrGroupPolicy",
      "admin:ListUserPolicies"]},
    {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:ListBucketVersions"], "Resource": ["arn:aws:s3:::tf-state"],
     "Condition": {"StringLike": {"s3:prefix": ["tenants/*"]}}},
    {"Effect": "Allow", "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"],
     "Resource": ["arn:aws:s3:::tf-state/tenants/*"]}
  ]
}`

func TestPurgeRemovesEveryVersionUnderTheTenantOnly(t *testing.T) {
	ep := os.Getenv("DEEVNET_TEST_MINIO_ENDPOINT")
	if ep == "" {
		t.Skip("DEEVNET_TEST_MINIO_ENDPOINT not set")
	}
	ctx := context.Background()
	rootKey, rootSecret := os.Getenv("DEEVNET_TEST_MINIO_ACCESS_KEY"), os.Getenv("DEEVNET_TEST_MINIO_SECRET_KEY")
	root, err := New(ep, rootKey, rootSecret, false, "")
	if err != nil {
		t.Fatal(err)
	}

	// A versioned bucket holding the tenant's state written twice and then
	// deleted (so a delete marker over two versions), another tenant's state,
	// and the fabric's, outside tenants/.
	const bucket = "tf-state"
	if ok, err := root.s3.BucketExists(ctx, bucket); err != nil {
		t.Fatal(err)
	} else if !ok {
		if err := root.s3.MakeBucket(ctx, bucket, miniogo.MakeBucketOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := root.s3.EnableVersioning(ctx, bucket); err != nil {
		t.Fatal(err)
	}
	put := func(key, body string) {
		t.Helper()
		if _, err := root.s3.PutObject(ctx, bucket, key, strings.NewReader(body), int64(len(body)), miniogo.PutObjectOptions{}); err != nil {
			t.Fatalf("put %s: %v", key, err)
		}
	}
	put("tenants/tprobe/terraform.tfstate", "v1")
	put("tenants/tprobe/terraform.tfstate", "v2")
	put("tenants/tprobe/terraform.tfstate.tflock", "lock")
	if err := root.s3.RemoveObject(ctx, bucket, "tenants/tprobe/terraform.tfstate.tflock", miniogo.RemoveObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	put("tenants/tprobe2/terraform.tfstate", "neighbour")
	put("fabric/terraform.tfstate", "fabric")
	t.Cleanup(func() {
		for _, p := range []string{"tenants/tprobe2/", "fabric/"} {
			for o := range root.s3.ListObjects(context.Background(), bucket, miniogo.ListObjectsOptions{Prefix: p, Recursive: true, WithVersions: true}) {
				_ = root.s3.RemoveObject(context.Background(), bucket, o.Key, miniogo.RemoveObjectOptions{VersionID: o.VersionID})
			}
		}
	})

	// The API's user, with the role's policy.
	const apiUser, apiSecret = "it-deevnet-api", "it-deevnet-api-secret"
	if err := root.admin.AddCannedPolicy(ctx, "it-deevnet-api-admin", []byte(apiAdminPolicy)); err != nil {
		t.Fatal(err)
	}
	if err := root.admin.AddUser(ctx, apiUser, apiSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := root.admin.AttachPolicy(ctx, madmin.PolicyAssociationReq{Policies: []string{"it-deevnet-api-admin"}, User: apiUser}); err != nil &&
		!hasCode(err, "XMinioAdminPolicyChangeAlreadyApplied") {
		t.Fatal(err)
	}
	api, err := New(ep, apiUser, apiSecret, false, "")
	if err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{"", "tenants/", "fabric/", "tenants/tprobe", "tenants/../fabric/"} {
		if err := api.Purge(ctx, bucket, bad); err == nil {
			t.Errorf("purge of %q was not refused", bad)
		}
	}
	if err := api.Purge(ctx, bucket, "tenants/tprobe/"); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if err := api.Purge(ctx, bucket, "tenants/tprobe/"); err != nil {
		t.Fatalf("purge again: %v", err)
	}

	count := func(prefix string) int {
		n := 0
		for o := range root.s3.ListObjects(ctx, bucket, miniogo.ListObjectsOptions{Prefix: prefix, Recursive: true, WithVersions: true}) {
			if o.Err != nil {
				t.Fatal(o.Err)
			}
			n++
		}
		return n
	}
	if n := count("tenants/tprobe/"); n != 0 {
		t.Errorf("%d versions left under the purged tenant", n)
	}
	if n := count("tenants/tprobe2/"); n != 1 {
		t.Errorf("the neighbouring tenant has %d versions, want 1 untouched", n)
	}
	if n := count("fabric/"); n != 1 {
		t.Errorf("the fabric's state has %d versions, want 1 untouched", n)
	}

	// The policy, not only the prefix check, keeps the API out of the fabric.
	err = api.s3.RemoveObject(ctx, bucket, "fabric/terraform.tfstate", miniogo.RemoveObjectOptions{})
	if err == nil || miniogo.ToErrorResponse(err).Code != "AccessDenied" {
		t.Errorf("the API user deleting the fabric's state: %v, want AccessDenied", err)
	}
}

// CHG-0030: over TLS the admin client verifies the state store against the
// site CA it is given - it reaches a server whose certificate that CA signed,
// refuses one it did not, and there is no way to ask it to skip verification.
func TestTLSVerifiesAgainstTheGivenCA(t *testing.T) {
	var reached atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")

	caFile := filepath.Join(t.TempDir(), "site-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := New(host, "deevnet-api", "s", true, caFile)
	if err != nil {
		t.Fatal(err)
	}
	ctx0, cancel0 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel0()
	_ = c.Remove(ctx0, "tprobe")
	if !reached.Load() {
		t.Fatal("with the right CA the request never reached the server")
	}

	// A CA that did not sign the server's certificate: the handshake fails and
	// the request never arrives. Generated here, because every httptest TLS
	// server shares one built-in certificate - a second server's would verify.
	wrongCA := filepath.Join(t.TempDir(), "wrong-ca.pem")
	_ = os.WriteFile(wrongCA, unrelatedCA(t), 0o600)
	reached.Store(false)
	c, err = New(host, "deevnet-api", "s", true, wrongCA)
	if err != nil {
		t.Fatal(err)
	}
	// Bounded: the admin client retries a failed handshake with backoff.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Remove(ctx, "tprobe"); err == nil || reached.Load() {
		t.Fatalf("a server the CA did not sign was accepted: err=%v reached=%v", err, reached.Load())
	}

	// TLS without a CA is a configuration error, not a fallback to skipping.
	if _, err := New(host, "deevnet-api", "s", true, ""); err == nil {
		t.Error("TLS with no CA file was accepted")
	}
	if _, err := New(host, "deevnet-api", "s", true, filepath.Join(t.TempDir(), "absent.pem")); err == nil {
		t.Error("a CA file that does not exist was accepted")
	}
}

// unrelatedCA is a self-signed CA certificate that signed nothing here.
func unrelatedCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "not the site CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
