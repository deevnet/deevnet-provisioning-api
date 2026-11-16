package tenant

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"time"
)

// Tenant buckets in the bucket store (ADR-0026 §3, §5; CHG-0069). An optional
// service: a site with no bucket store leaves Service.Buckets nil, and its
// routes answer ErrBucketsNotOffered.
//
// Four rules carry the weight:
//
//   - A bucket is "<tenant>-<name>" in the store. Tenant names hold no dash,
//     so the first dash says whose it is and two tenants never share one.
//   - Quotas are allocated, never overcommitted. The sum over every tenant's
//     buckets stays within the configured capacity, and the registry checks
//     that under the allocation lock, so two creates cannot both take the
//     last of it.
//   - Each key is a store user whose policy reaches its one bucket and nothing
//     else. The user is the key's access key, as a plain store user is; its
//     policy is "<bucket>.<key>", which no other bucket's key can be named.
//   - A key's secret is kept sealed, as a Wi-Fi key is, because the store
//     needs the plaintext to make the user again on a reconcile. It is
//     returned in a create response and never on a read.

const (
	// StepBuckets is the bucket store: a bucket, its settings and its keys.
	StepBuckets = "buckets"

	// DefaultBucketKey is the key made with every bucket.
	DefaultBucketKey = "default"

	BucketAccessRead  = "read"
	BucketAccessWrite = "write"

	accessKeyLength = 20
	secretKeyLength = 40
	accessKeyChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	secretKeyChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	maxStoreBucket  = 63
)

var (
	// ErrBucketsNotOffered: the API has no bucket store configured.
	ErrBucketsNotOffered = errors.New("this site has no bucket store")
	// ErrBucketNotFound and ErrBucketKeyNotFound are the registry's not-found
	// for a bucket or a key, told apart from the tenant's own.
	ErrBucketNotFound    = errors.New("bucket not found")
	ErrBucketKeyNotFound = errors.New("bucket key not found")
	// ErrBucketExists and ErrBucketKeyExists: the name is taken.
	ErrBucketExists    = errors.New("a bucket with that name already exists")
	ErrBucketKeyExists = errors.New("a key with that name already exists on this bucket")
	// ErrBucketNotEmpty: a delete without force, of a bucket that holds any
	// object version or delete marker.
	ErrBucketNotEmpty = errors.New("the bucket is not empty; delete with force=true to remove it and everything in it")

	bucketNameRE    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}[a-z0-9]$`)
	bucketKeyNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,19}$`)
)

// CapacityError is a create or a quota increase the bucket store has no room
// for. It names what is left, which is all a tenant can act on.
type CapacityError struct {
	RequestedGB int
	FreeGB      int
	CapacityGB  int
}

func (e *CapacityError) Error() string {
	return fmt.Sprintf("the bucket store has %d GB of %d GB left to allocate; this needs %d GB", e.FreeGB, e.CapacityGB, e.RequestedGB)
}

// Bucket is a tenant's bucket as the registry holds it.
type Bucket struct {
	Tenant     string
	Name       string
	QuotaGB    int
	Versioning bool
	// ExpireDays and NoncurrentExpireDays are lifecycle rules; 0 is none.
	ExpireDays           int
	NoncurrentExpireDays int
	PublicRead           bool
	Status               Status
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// StoreName is the bucket's name in the store: "<tenant>-<name>".
func (b Bucket) StoreName() string { return BucketStoreName(b.Tenant, b.Name) }

// BucketStoreName is "<tenant>-<name>".
func BucketStoreName(tenantName, name string) string { return tenantName + "-" + name }

// BucketKey is one key to a bucket, as the registry holds it.
type BucketKey struct {
	Tenant string
	Bucket string
	Name   string
	Access string
	// AccessKey is the store user's name: generated, 20 of [A-Z0-9].
	AccessKey string
	// SecretKey is sealed at rest and returned in a create response only.
	SecretKey string
	// Unreadable: the stored secret would not open, as Secrets.Unreadable.
	Unreadable bool
	Status     Status
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// BucketKeyPolicyName is the store policy that confines one key: the bucket's
// store name, a dot, and the key's name. A dot is in neither a bucket nor a
// key name, so no two keys anywhere share one.
func BucketKeyPolicyName(storeBucket, key string) string { return storeBucket + "." + key }

// BucketSpec is a bucket as the store needs it.
type BucketSpec struct {
	// Bucket is the store name, "<tenant>-<name>".
	Bucket               string
	QuotaGB              int
	Versioning           bool
	ExpireDays           int
	NoncurrentExpireDays int
	PublicRead           bool
}

// BucketKeySpec is one key as the store needs it: a user, a policy reaching
// one bucket, and the attachment between them.
type BucketKeySpec struct {
	Bucket    string
	Policy    string
	AccessKey string
	SecretKey string
	Access    string
}

// BucketStore is the store tenant buckets live in. Every call is an ensure:
// absent is success for a remove, present is success for a make.
type BucketStore interface {
	// EnsureBucket makes the bucket and brings its quota, versioning,
	// lifecycle and bucket policy into line. Versioning that was on and is
	// asked off is suspended: S3 cannot un-version a bucket.
	EnsureBucket(ctx context.Context, b BucketSpec) error
	// BucketHasObjects reports whether the bucket holds any object version or
	// delete marker. An absent bucket holds none.
	BucketHasObjects(ctx context.Context, bucket string) (bool, error)
	// RemoveBucket deletes the bucket. With purge, every version and delete
	// marker goes first; without it, a bucket that is not empty is refused
	// with ErrBucketNotEmpty.
	RemoveBucket(ctx context.Context, bucket string, purge bool) error
	// EnsureKey makes the key's policy and user and attaches one to the other.
	EnsureKey(ctx context.Context, k BucketKeySpec) error
	// RemoveKey deletes the user and its policy.
	RemoveKey(ctx context.Context, accessKey, policy string) error
}

// BucketRequest is a tenant declaring a bucket, or changing one.
type BucketRequest struct {
	Name                 string
	QuotaGB              int
	Versioning           bool
	ExpireDays           int
	NoncurrentExpireDays int
	PublicRead           bool
}

// BucketKeyRequest is a tenant asking for a key to one of its buckets.
type BucketKeyRequest struct {
	Name   string
	Access string
}

// ValidBucketName reports whether name can be a tenant's bucket.
func ValidBucketName(name string) bool { return bucketNameRE.MatchString(name) }

// ValidBucketKeyName reports whether name can be a bucket's key.
func ValidBucketKeyName(name string) bool { return bucketKeyNameRE.MatchString(name) }

// ValidateBucket applies the API's rules for a new bucket: its name, the
// length of its store name, and its settings. deevnet-kit applies the same
// rules on a take-home Pi (CHG-0073).
func ValidateBucket(tenantName string, req BucketRequest) error {
	if !ValidBucketName(req.Name) {
		return invalid("bucket name must be 3-32 lowercase alphanumerics or dashes, starting with a letter and ending with a letter or digit")
	}
	if n := len(BucketStoreName(tenantName, req.Name)); n > maxStoreBucket {
		return invalid("bucket name is too long: %q is %d characters, and the store allows %d", BucketStoreName(tenantName, req.Name), n, maxStoreBucket)
	}
	return validateBucketSettings(req)
}

// ValidBucketAccess reports whether a is a key's access: read or write.
func ValidBucketAccess(a string) bool { return validAccess(a) }

// NewBucketCredentials mints a key's access key and secret as the API does.
func NewBucketCredentials() (accessKey, secretKey string, err error) {
	if accessKey, err = randomString(accessKeyChars, accessKeyLength); err != nil {
		return "", "", err
	}
	if secretKey, err = randomString(secretKeyChars, secretKeyLength); err != nil {
		return "", "", err
	}
	return accessKey, secretKey, nil
}

func validateBucketSettings(req BucketRequest) error {
	if req.QuotaGB < 1 {
		return invalid("quota_gb must be 1 or more")
	}
	if req.ExpireDays < 0 {
		return invalid("lifecycle.expire_days must be 0 (none) or more")
	}
	if req.NoncurrentExpireDays < 0 {
		return invalid("lifecycle.noncurrent_expire_days must be 0 (none) or more")
	}
	return nil
}

func validAccess(a string) bool { return a == BucketAccessRead || a == BucketAccessWrite }

// bucketsTenant checks the service is offered and the tenant is ready.
func (s *Service) bucketsTenant(ctx context.Context, tenantName string) error {
	if s.Buckets == nil {
		return ErrBucketsNotOffered
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

func bucketsStep(err error) error { return &StepError{Step: StepBuckets, Err: err} }

func bucketSpec(b Bucket) BucketSpec {
	return BucketSpec{
		Bucket:               b.StoreName(),
		QuotaGB:              b.QuotaGB,
		Versioning:           b.Versioning,
		ExpireDays:           b.ExpireDays,
		NoncurrentExpireDays: b.NoncurrentExpireDays,
		PublicRead:           b.PublicRead,
	}
}

func bucketKeySpec(k BucketKey) BucketKeySpec {
	storeBucket := BucketStoreName(k.Tenant, k.Bucket)
	return BucketKeySpec{
		Bucket:    storeBucket,
		Policy:    BucketKeyPolicyName(storeBucket, k.Name),
		AccessKey: k.AccessKey,
		SecretKey: k.SecretKey,
		Access:    k.Access,
	}
}

// getBucket reads a bucket, its not-found told apart from the tenant's.
func (s *Service) getBucket(ctx context.Context, tenantName, name string) (Bucket, error) {
	b, err := s.Store.GetBucket(ctx, tenantName, name)
	if errors.Is(err, ErrNotFound) {
		return Bucket{}, ErrBucketNotFound
	}
	return b, err
}

func (s *Service) getBucketKey(ctx context.Context, tenantName, bucket, name string) (BucketKey, error) {
	k, err := s.Store.GetBucketKey(ctx, tenantName, bucket, name)
	if errors.Is(err, ErrNotFound) {
		return BucketKey{}, ErrBucketKeyNotFound
	}
	return k, err
}

// CreateBucket makes a bucket and its default key, and returns both, the
// key with its secret.
//
// The rows go down first, with status provisioning, and the store is called
// after: a retry of a create that failed half way finds them and converges on
// the same bucket and the same key, rather than minting a second. A bucket
// already ready is a duplicate.
func (s *Service) CreateBucket(ctx context.Context, tenantName string, req BucketRequest) (Bucket, BucketKey, error) {
	if err := s.bucketsTenant(ctx, tenantName); err != nil {
		return Bucket{}, BucketKey{}, err
	}
	if err := ValidateBucket(tenantName, req); err != nil {
		return Bucket{}, BucketKey{}, err
	}

	existing, err := s.Store.GetBucket(ctx, tenantName, req.Name)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return Bucket{}, BucketKey{}, err
	case existing.Status != StatusProvisioning:
		return Bucket{}, BucketKey{}, ErrBucketExists
	}

	b, err := s.Store.PutBucket(ctx, Bucket{
		Tenant: tenantName, Name: req.Name, QuotaGB: req.QuotaGB, Versioning: req.Versioning,
		ExpireDays: req.ExpireDays, NoncurrentExpireDays: req.NoncurrentExpireDays,
		PublicRead: req.PublicRead, Status: StatusProvisioning,
	}, s.BucketCapacityGB)
	if err != nil {
		return Bucket{}, BucketKey{}, err
	}

	// The default key: the one a failed create already made, else a new one.
	k, err := s.Store.GetBucketKey(ctx, tenantName, req.Name, DefaultBucketKey)
	switch {
	case errors.Is(err, ErrNotFound):
		k = BucketKey{Tenant: tenantName, Bucket: req.Name, Name: DefaultBucketKey, Access: BucketAccessWrite}
	case err != nil:
		return b, BucketKey{}, err
	}
	if k, err = s.putBucketKey(ctx, k); err != nil {
		return b, BucketKey{}, err
	}
	s.audit(ctx, "bucket-create", tenantName, map[string]any{
		"bucket": b.Name, "quota_gb": b.QuotaGB, "versioning": b.Versioning,
		"expire_days": b.ExpireDays, "noncurrent_expire_days": b.NoncurrentExpireDays,
		"public_read": b.PublicRead,
	})

	if err := s.Buckets.EnsureBucket(ctx, bucketSpec(b)); err != nil {
		s.logger().Error("making bucket", "tenant", tenantName, "bucket", b.Name, "err", err)
		return b, k, bucketsStep(err)
	}
	if err := s.Buckets.EnsureKey(ctx, bucketKeySpec(k)); err != nil {
		s.logger().Error("making bucket key", "tenant", tenantName, "bucket", b.Name, "key", k.Name, "err", err)
		return b, k, bucketsStep(err)
	}
	if err := s.Store.SetBucketKeyStatus(ctx, tenantName, b.Name, k.Name, StatusReady); err != nil {
		return b, k, err
	}
	k.Status = StatusReady
	if err := s.Store.SetBucketStatus(ctx, tenantName, b.Name, StatusReady); err != nil {
		return b, k, err
	}
	b.Status = StatusReady
	return b, k, nil
}

// putBucketKey keeps a key's access key and secret if it has them, mints
// what it lacks, and writes the row with status provisioning. A secret that
// will not open is replaced: the key is being made, so nobody holds it yet.
func (s *Service) putBucketKey(ctx context.Context, k BucketKey) (BucketKey, error) {
	var err error
	if k.AccessKey == "" {
		if k.AccessKey, err = randomString(accessKeyChars, accessKeyLength); err != nil {
			return BucketKey{}, err
		}
	}
	if k.SecretKey == "" || k.Unreadable {
		if k.SecretKey, err = randomString(secretKeyChars, secretKeyLength); err != nil {
			return BucketKey{}, err
		}
		k.Unreadable = false
	}
	k.Status = StatusProvisioning
	return s.Store.PutBucketKey(ctx, k)
}

// UpdateBucket changes a bucket's quota, versioning, lifecycle and anonymous
// read. Admission applies to a quota increase.
func (s *Service) UpdateBucket(ctx context.Context, tenantName, name string, req BucketRequest) (Bucket, error) {
	if s.Buckets == nil {
		return Bucket{}, ErrBucketsNotOffered
	}
	old, err := s.getBucket(ctx, tenantName, name)
	if err != nil {
		return Bucket{}, err
	}
	if old.Status == StatusDeleting {
		return Bucket{}, invalid("bucket %q is being deleted", name)
	}
	if err := validateBucketSettings(req); err != nil {
		return Bucket{}, err
	}
	b, err := s.Store.PutBucket(ctx, Bucket{
		Tenant: tenantName, Name: name, QuotaGB: req.QuotaGB, Versioning: req.Versioning,
		ExpireDays: req.ExpireDays, NoncurrentExpireDays: req.NoncurrentExpireDays,
		PublicRead: req.PublicRead, Status: StatusProvisioning,
	}, s.BucketCapacityGB)
	if err != nil {
		return Bucket{}, err
	}
	s.audit(ctx, "bucket-update", tenantName, map[string]any{
		"bucket": b.Name, "quota_gb": b.QuotaGB, "versioning": b.Versioning,
		"expire_days": b.ExpireDays, "noncurrent_expire_days": b.NoncurrentExpireDays,
		"public_read": b.PublicRead,
	})
	if err := s.Buckets.EnsureBucket(ctx, bucketSpec(b)); err != nil {
		s.logger().Error("updating bucket", "tenant", tenantName, "bucket", b.Name, "err", err)
		return b, bucketsStep(err)
	}
	if err := s.Store.SetBucketStatus(ctx, tenantName, name, StatusReady); err != nil {
		return b, err
	}
	b.Status = StatusReady
	return b, nil
}

// GetBucket returns one bucket.
func (s *Service) GetBucket(ctx context.Context, tenantName, name string) (Bucket, error) {
	if s.Buckets == nil {
		return Bucket{}, ErrBucketsNotOffered
	}
	return s.getBucket(ctx, tenantName, name)
}

// ListBuckets returns a tenant's buckets.
func (s *Service) ListBuckets(ctx context.Context, tenantName string) ([]Bucket, error) {
	if s.Buckets == nil {
		return nil, ErrBucketsNotOffered
	}
	if _, err := s.Store.Get(ctx, tenantName); err != nil {
		return nil, err
	}
	return s.Store.ListBuckets(ctx, tenantName)
}

// DeleteBucket removes a bucket, its keys and their policies. Without force,
// a bucket holding any object version or delete marker is refused before
// anything changes; with it, everything in it goes first.
func (s *Service) DeleteBucket(ctx context.Context, tenantName, name string, force bool) error {
	if s.Buckets == nil {
		return ErrBucketsNotOffered
	}
	b, err := s.getBucket(ctx, tenantName, name)
	if err != nil {
		return err
	}
	if !force {
		full, err := s.Buckets.BucketHasObjects(ctx, b.StoreName())
		if err != nil {
			return bucketsStep(err)
		}
		if full {
			return ErrBucketNotEmpty
		}
	}
	if err := s.Store.SetBucketStatus(ctx, tenantName, name, StatusDeleting); err != nil {
		return err
	}
	s.audit(ctx, "bucket-delete", tenantName, map[string]any{"bucket": name, "force": force})
	if err := s.removeBucket(ctx, b, force); err != nil {
		return err
	}
	return s.Store.DeleteBucket(ctx, tenantName, name)
}

// removeBucket takes a bucket out of the store: its keys first, so nothing
// writes while it empties, then the bucket.
func (s *Service) removeBucket(ctx context.Context, b Bucket, purge bool) error {
	keys, err := s.Store.ListBucketKeys(ctx, b.Tenant, b.Name)
	if err != nil {
		return err
	}
	for _, k := range keys {
		spec := bucketKeySpec(k)
		if err := s.Buckets.RemoveKey(ctx, spec.AccessKey, spec.Policy); err != nil {
			return bucketsStep(err)
		}
	}
	if err := s.Buckets.RemoveBucket(ctx, b.StoreName(), purge); err != nil {
		if errors.Is(err, ErrBucketNotEmpty) {
			return ErrBucketNotEmpty
		}
		return bucketsStep(err)
	}
	return nil
}

// CreateBucketKey makes a further key to a bucket, and returns it with its
// secret. A key a failed create left provisioning is resumed with the same
// access key and secret; one already ready is a duplicate.
func (s *Service) CreateBucketKey(ctx context.Context, tenantName, bucket string, req BucketKeyRequest) (BucketKey, error) {
	if err := s.bucketsTenant(ctx, tenantName); err != nil {
		return BucketKey{}, err
	}
	b, err := s.getBucket(ctx, tenantName, bucket)
	if err != nil {
		return BucketKey{}, err
	}
	if !ValidBucketKeyName(req.Name) {
		return BucketKey{}, invalid("key name must be 1-20 lowercase alphanumerics or dashes, starting with a letter")
	}
	if !validAccess(req.Access) {
		return BucketKey{}, invalid("access must be %q or %q", BucketAccessRead, BucketAccessWrite)
	}
	if b.Status != StatusReady {
		return BucketKey{}, invalid("bucket %q is %s", bucket, b.Status)
	}

	k, err := s.Store.GetBucketKey(ctx, tenantName, bucket, req.Name)
	switch {
	case errors.Is(err, ErrNotFound):
		k = BucketKey{Tenant: tenantName, Bucket: bucket, Name: req.Name}
	case err != nil:
		return BucketKey{}, err
	case k.Status != StatusProvisioning:
		return BucketKey{}, ErrBucketKeyExists
	}
	k.Access = req.Access
	if k, err = s.putBucketKey(ctx, k); err != nil {
		return BucketKey{}, err
	}
	s.audit(ctx, "bucket-key-create", tenantName, map[string]any{
		"bucket": bucket, "key": k.Name, "access": k.Access, "access_key": k.AccessKey,
	})
	if err := s.Buckets.EnsureKey(ctx, bucketKeySpec(k)); err != nil {
		s.logger().Error("making bucket key", "tenant", tenantName, "bucket", bucket, "key", k.Name, "err", err)
		return k, bucketsStep(err)
	}
	if err := s.Store.SetBucketKeyStatus(ctx, tenantName, bucket, k.Name, StatusReady); err != nil {
		return k, err
	}
	k.Status = StatusReady
	return k, nil
}

// GetBucketKey returns one key. The caller never hands its secret on.
func (s *Service) GetBucketKey(ctx context.Context, tenantName, bucket, name string) (BucketKey, error) {
	if s.Buckets == nil {
		return BucketKey{}, ErrBucketsNotOffered
	}
	if _, err := s.getBucket(ctx, tenantName, bucket); err != nil {
		return BucketKey{}, err
	}
	return s.getBucketKey(ctx, tenantName, bucket, name)
}

// ListBucketKeys returns a bucket's keys.
func (s *Service) ListBucketKeys(ctx context.Context, tenantName, bucket string) ([]BucketKey, error) {
	if s.Buckets == nil {
		return nil, ErrBucketsNotOffered
	}
	if _, err := s.getBucket(ctx, tenantName, bucket); err != nil {
		return nil, err
	}
	return s.Store.ListBucketKeys(ctx, tenantName, bucket)
}

// DeleteBucketKey revokes a key: the store user and its policy, then the row.
// The default key is deleted like any other.
func (s *Service) DeleteBucketKey(ctx context.Context, tenantName, bucket, name string) error {
	if s.Buckets == nil {
		return ErrBucketsNotOffered
	}
	if _, err := s.getBucket(ctx, tenantName, bucket); err != nil {
		return err
	}
	k, err := s.getBucketKey(ctx, tenantName, bucket, name)
	if err != nil {
		return err
	}
	spec := bucketKeySpec(k)
	if err := s.Buckets.RemoveKey(ctx, spec.AccessKey, spec.Policy); err != nil {
		return bucketsStep(err)
	}
	s.audit(ctx, "bucket-key-delete", tenantName, map[string]any{"bucket": bucket, "key": name})
	return s.Store.DeleteBucketKey(ctx, tenantName, bucket, name)
}

// ensureBuckets is the reconcile step: every bucket and every key the
// registry holds is made again in the store and brought into line. One being
// deleted is left to its delete. A key whose secret will not open cannot be
// made again and is skipped, with the reason in the log; the rest go on.
func (s *Service) ensureBuckets(ctx context.Context, rec Record) error {
	buckets, err := s.Store.ListBuckets(ctx, rec.Name)
	if err != nil {
		return err
	}
	for _, b := range buckets {
		if b.Status == StatusDeleting {
			continue
		}
		if err := s.Buckets.EnsureBucket(ctx, bucketSpec(b)); err != nil {
			return err
		}
		keys, err := s.Store.ListBucketKeys(ctx, rec.Name, b.Name)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if k.Status == StatusDeleting {
				continue
			}
			if k.Unreadable {
				s.logger().Error("bucket key secret will not open; the key cannot be made again until it is replaced",
					"tenant", rec.Name, "bucket", b.Name, "key", k.Name)
				continue
			}
			if err := s.Buckets.EnsureKey(ctx, bucketKeySpec(k)); err != nil {
				return err
			}
			if k.Status != StatusReady {
				if err := s.Store.SetBucketKeyStatus(ctx, rec.Name, b.Name, k.Name, StatusReady); err != nil {
					return err
				}
			}
		}
		if b.Status != StatusReady {
			if err := s.Store.SetBucketStatus(ctx, rec.Name, b.Name, StatusReady); err != nil {
				return err
			}
		}
	}
	return nil
}

// removeBuckets is tenant removal's step: every bucket goes, with everything
// in it, and every key and policy. The rows go with the tenant's.
func (s *Service) removeBuckets(ctx context.Context, rec Record) error {
	buckets, err := s.Store.ListBuckets(ctx, rec.Name)
	if err != nil {
		return err
	}
	for _, b := range buckets {
		if err := s.removeBucket(ctx, b, true); err != nil {
			var step *StepError
			if errors.As(err, &step) {
				return step.Err
			}
			return err
		}
	}
	return nil
}

// randomString draws n characters uniformly from alphabet with crypto/rand.
func randomString(alphabet string, n int) (string, error) {
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = alphabet[v.Int64()]
	}
	return string(out), nil
}
