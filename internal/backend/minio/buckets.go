package minio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/minio/madmin-go/v3"
	miniogo "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/lifecycle"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Buckets is a tenant.BucketStore: the bucket store tenants' own buckets live
// in (ADR-0026 §3, CHG-0069). A second store, separate from the state store,
// driven with the same admin credential pair.
//
// Each key is a plain store user named by its access key, not a service
// account (ADR-0026 §1), with a canned policy that reaches its one bucket and
// nothing else. Bucket requests are path-style: the store is one name, reached
// through a TLS service proxy.
type Buckets struct {
	admin *madmin.AdminClient
	s3    *miniogo.Client
}

var _ tenant.BucketStore = (*Buckets)(nil)

// gib is one quota_gb in bytes.
const gib = 1 << 30

// Lifecycle rule IDs the API owns. A rule with another ID is not the API's,
// and a bucket whose rules differ from what the API would write is rewritten.
const (
	ruleExpire           = "deevnet-expire"
	ruleNoncurrentExpire = "deevnet-noncurrent-expire"
)

// NewBuckets takes host[:port], for example s3.mobile.deevnet.net, and the
// API's own admin credential. TLS always: caFile is the site CA the store's
// certificate must verify against, the one the state store client uses.
func NewBuckets(endpoint, accessKey, secretKey, caFile string) (*Buckets, error) {
	a, s3, err := connect(endpoint, accessKey, secretKey, true, caFile, miniogo.BucketLookupPath)
	if err != nil {
		return nil, err
	}
	return &Buckets{admin: a, s3: s3}, nil
}

// KeyPolicy is a key's confinement to one bucket. write lists, gets, puts and
// deletes objects and their versions; read lists and gets them. Both may ask
// where the bucket is, which S3 clients do before anything else.
func KeyPolicy(bucket, access string) ([]byte, error) {
	var bucketActions, objectActions []string
	switch access {
	case tenant.BucketAccessWrite:
		bucketActions = []string{"s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"}
		objectActions = []string{
			"s3:GetObject", "s3:GetObjectVersion",
			"s3:PutObject",
			"s3:DeleteObject", "s3:DeleteObjectVersion",
			"s3:AbortMultipartUpload", "s3:ListMultipartUploadParts",
		}
	case tenant.BucketAccessRead:
		bucketActions = []string{"s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketVersions"}
		objectActions = []string{"s3:GetObject", "s3:GetObjectVersion"}
	default:
		return nil, fmt.Errorf("access %q is neither read nor write", access)
	}
	return json.Marshal(policyDoc{
		Version: "2012-10-17",
		Statement: []policyStatement{
			{Effect: "Allow", Action: bucketActions, Resource: []string{"arn:aws:s3:::" + bucket}},
			{Effect: "Allow", Action: objectActions, Resource: []string{"arn:aws:s3:::" + bucket + "/*"}},
		},
	})
}

// PublicReadPolicy is the bucket policy of a public_read bucket: anonymous
// GetObject on its objects, and nothing else - no listing (ADR-0026 §5).
func PublicReadPolicy(bucket string) ([]byte, error) {
	return json.Marshal(policyDoc{
		Version: "2012-10-17",
		Statement: []policyStatement{{
			Effect:    "Allow",
			Principal: map[string][]string{"AWS": {"*"}},
			Action:    []string{"s3:GetObject"},
			Resource:  []string{"arn:aws:s3:::" + bucket + "/*"},
		}},
	})
}

type policyDoc struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Effect    string              `json:"Effect"`
	Principal map[string][]string `json:"Principal,omitempty"`
	Action    []string            `json:"Action"`
	Resource  []string            `json:"Resource"`
}

// Lifecycle is the rules a bucket's settings ask for, nil for none.
func Lifecycle(b tenant.BucketSpec) *lifecycle.Configuration {
	cfg := lifecycle.NewConfiguration()
	if b.ExpireDays > 0 {
		cfg.Rules = append(cfg.Rules, lifecycle.Rule{
			ID: ruleExpire, Status: "Enabled",
			Expiration: lifecycle.Expiration{Days: lifecycle.ExpirationDays(b.ExpireDays)},
		})
	}
	if b.NoncurrentExpireDays > 0 {
		cfg.Rules = append(cfg.Rules, lifecycle.Rule{
			ID: ruleNoncurrentExpire, Status: "Enabled",
			NoncurrentVersionExpiration: lifecycle.NoncurrentVersionExpiration{NoncurrentDays: lifecycle.ExpirationDays(b.NoncurrentExpireDays)},
		})
	}
	return cfg
}

// EnsureBucket makes the bucket if it is absent, then reads and corrects its
// quota, versioning, lifecycle and bucket policy, one at a time.
func (c *Buckets) EnsureBucket(ctx context.Context, b tenant.BucketSpec) error {
	exists, err := c.s3.BucketExists(ctx, b.Bucket)
	if err != nil {
		return fmt.Errorf("bucket %s: %w", b.Bucket, err)
	}
	if !exists {
		if err := c.s3.MakeBucket(ctx, b.Bucket, miniogo.MakeBucketOptions{}); err != nil && !s3Code(err, "BucketAlreadyOwnedByYou") {
			return fmt.Errorf("make bucket %s: %w", b.Bucket, err)
		}
	}

	// The quota. Size is what the store reads; Quota is its older name,
	// still set so an older server reads the same.
	want := uint64(b.QuotaGB) * gib
	q, err := c.admin.GetBucketQuota(ctx, b.Bucket)
	if err != nil {
		return fmt.Errorf("quota of %s: %w", b.Bucket, err)
	}
	if q.Type != madmin.HardQuota || (q.Size != want && q.Quota != want) {
		if err := c.admin.SetBucketQuota(ctx, b.Bucket, &madmin.BucketQuota{Size: want, Quota: want, Type: madmin.HardQuota}); err != nil {
			return fmt.Errorf("set quota of %s: %w", b.Bucket, err)
		}
	}

	// Versioning. Off after on is Suspended: S3 cannot un-version a bucket.
	v, err := c.s3.GetBucketVersioning(ctx, b.Bucket)
	if err != nil {
		return fmt.Errorf("versioning of %s: %w", b.Bucket, err)
	}
	switch {
	case b.Versioning && v.Status != "Enabled":
		err = c.s3.EnableVersioning(ctx, b.Bucket)
	case !b.Versioning && v.Status == "Enabled":
		err = c.s3.SuspendVersioning(ctx, b.Bucket)
	}
	if err != nil {
		return fmt.Errorf("set versioning of %s: %w", b.Bucket, err)
	}

	// Lifecycle.
	wantLC := Lifecycle(b)
	haveLC, err := c.s3.GetBucketLifecycle(ctx, b.Bucket)
	if err != nil && !s3Code(err, "NoSuchLifecycleConfiguration") {
		return fmt.Errorf("lifecycle of %s: %w", b.Bucket, err)
	}
	if !sameLifecycle(haveLC, wantLC) {
		if err := c.s3.SetBucketLifecycle(ctx, b.Bucket, wantLC); err != nil {
			return fmt.Errorf("set lifecycle of %s: %w", b.Bucket, err)
		}
	}

	// Anonymous read.
	var wantPol string
	if b.PublicRead {
		raw, err := PublicReadPolicy(b.Bucket)
		if err != nil {
			return err
		}
		wantPol = string(raw)
	}
	havePol, err := c.s3.GetBucketPolicy(ctx, b.Bucket)
	if err != nil {
		return fmt.Errorf("policy of %s: %w", b.Bucket, err)
	}
	if !samePolicy(havePol, wantPol) {
		if err := c.s3.SetBucketPolicy(ctx, b.Bucket, wantPol); err != nil {
			return fmt.Errorf("set policy of %s: %w", b.Bucket, err)
		}
	}
	return nil
}

// sameLifecycle compares the rules that matter: ID, status, and the two
// expiries the API sets.
func sameLifecycle(have, want *lifecycle.Configuration) bool {
	type rule struct {
		ID, Status          string
		Days, NoncurrentDay int
	}
	norm := func(c *lifecycle.Configuration) []rule {
		if c == nil {
			return nil
		}
		var out []rule
		for _, r := range c.Rules {
			out = append(out, rule{r.ID, r.Status, int(r.Expiration.Days), int(r.NoncurrentVersionExpiration.NoncurrentDays)})
		}
		return out
	}
	return reflect.DeepEqual(norm(have), norm(want))
}

// samePolicy compares two policy documents by content, not spelling: the
// store may give back what it was sent with its keys in another order.
func samePolicy(have, want string) bool {
	if have == "" || want == "" {
		return have == want
	}
	var h, w any
	if json.Unmarshal([]byte(have), &h) != nil || json.Unmarshal([]byte(want), &w) != nil {
		return false
	}
	return reflect.DeepEqual(h, w)
}

// BucketHasObjects reports whether the bucket holds any object version or
// delete marker. An absent bucket holds none.
func (c *Buckets) BucketHasObjects(ctx context.Context, bucket string) (bool, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for o := range c.s3.ListObjects(ctx, bucket, miniogo.ListObjectsOptions{Recursive: true, WithVersions: true, MaxKeys: 1}) {
		if o.Err != nil {
			if s3Code(o.Err, "NoSuchBucket") {
				return false, nil
			}
			return false, fmt.Errorf("list versions in %s: %w", bucket, o.Err)
		}
		return true, nil
	}
	return false, nil
}

// RemoveBucket deletes the bucket; an absent one is success. With purge,
// every version and delete marker goes first. Without it, a bucket that is
// not empty answers tenant.ErrBucketNotEmpty.
func (c *Buckets) RemoveBucket(ctx context.Context, bucket string, purgeFirst bool) error {
	exists, err := c.s3.BucketExists(ctx, bucket)
	if err != nil {
		return fmt.Errorf("bucket %s: %w", bucket, err)
	}
	if !exists {
		return nil
	}
	if purgeFirst {
		if err := purge(ctx, c.s3, bucket, ""); err != nil {
			return err
		}
	}
	err = c.s3.RemoveBucket(ctx, bucket)
	switch {
	case err == nil, s3Code(err, "NoSuchBucket"):
		return nil
	case s3Code(err, "BucketNotEmpty"):
		return tenant.ErrBucketNotEmpty
	default:
		return fmt.Errorf("remove bucket %s: %w", bucket, err)
	}
}

// EnsureKey writes the key's policy, makes or updates its user with its
// secret, and attaches the one to the other.
func (c *Buckets) EnsureKey(ctx context.Context, k tenant.BucketKeySpec) error {
	pol, err := KeyPolicy(k.Bucket, k.Access)
	if err != nil {
		return err
	}
	if err := c.admin.AddCannedPolicy(ctx, k.Policy, pol); err != nil {
		return fmt.Errorf("policy %s: %w", k.Policy, err)
	}
	if err := c.admin.AddUser(ctx, k.AccessKey, k.SecretKey); err != nil {
		return fmt.Errorf("user for %s: %w", k.Policy, err)
	}
	_, err = c.admin.AttachPolicy(ctx, madmin.PolicyAssociationReq{Policies: []string{k.Policy}, User: k.AccessKey})
	if err != nil && !hasCode(err, "XMinioAdminPolicyChangeAlreadyApplied") {
		return fmt.Errorf("attach %s: %w", k.Policy, err)
	}
	return nil
}

// RemoveKey deletes the user, then its policy. Either absent is success.
func (c *Buckets) RemoveKey(ctx context.Context, accessKey, policy string) error {
	if err := c.admin.RemoveUser(ctx, accessKey); err != nil && !hasCode(err, "XMinioAdminNoSuchUser") {
		return fmt.Errorf("remove user for %s: %w", policy, err)
	}
	if err := c.admin.RemoveCannedPolicy(ctx, policy); err != nil && !hasCode(err, "XMinioAdminNoSuchPolicy") {
		return fmt.Errorf("remove policy %s: %w", policy, err)
	}
	return nil
}

func s3Code(err error, code string) bool {
	var er miniogo.ErrorResponse
	if errors.As(err, &er) {
		return er.Code == code
	}
	return miniogo.ToErrorResponse(err).Code == code
}
