package tenanttest

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// --- Buckets in the registry -------------------------------------------------

// PutBucket admits as the registry does: the sum of every other bucket's
// quota plus this one's must fit, unless the quota is not growing.
func (s *Store) PutBucket(_ context.Context, b tenant.Bucket, capacityGB int) (tenant.Bucket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[b.Tenant]; !ok {
		return tenant.Bucket{}, tenant.ErrNotFound
	}
	if s.buckets == nil {
		s.buckets = map[string]tenant.Bucket{}
	}
	key := b.Tenant + "/" + b.Name
	old, exists := s.buckets[key]
	others := 0
	for k, o := range s.buckets {
		if k != key {
			others += o.QuotaGB
		}
	}
	if b.QuotaGB > old.QuotaGB && others+b.QuotaGB > capacityGB {
		free := capacityGB - others
		if free < 0 {
			free = 0
		}
		return tenant.Bucket{}, &tenant.CapacityError{RequestedGB: b.QuotaGB, FreeGB: free, CapacityGB: capacityGB}
	}
	if exists {
		b.CreatedAt = old.CreatedAt
	} else {
		b.CreatedAt = time.Now()
	}
	b.UpdatedAt = time.Now()
	s.buckets[key] = b
	return b, nil
}

func (s *Store) GetBucket(_ context.Context, tenantName, name string) (tenant.Bucket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[tenantName+"/"+name]
	if !ok {
		return tenant.Bucket{}, tenant.ErrNotFound
	}
	return b, nil
}

func (s *Store) ListBuckets(_ context.Context, tenantName string) ([]tenant.Bucket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []tenant.Bucket
	for _, b := range s.buckets {
		if b.Tenant == tenantName {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) SetBucketStatus(_ context.Context, tenantName, name string, status tenant.Status) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[tenantName+"/"+name]
	if !ok {
		return tenant.ErrNotFound
	}
	b.Status = status
	s.buckets[tenantName+"/"+name] = b
	return nil
}

func (s *Store) DeleteBucket(_ context.Context, tenantName, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.buckets, tenantName+"/"+name)
	for key, k := range s.bucketKeys {
		if k.Tenant == tenantName && k.Bucket == name {
			delete(s.bucketKeys, key)
		}
	}
	return nil
}

func (s *Store) PutBucketKey(_ context.Context, k tenant.BucketKey) (tenant.BucketKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.buckets[k.Tenant+"/"+k.Bucket]; !ok {
		return tenant.BucketKey{}, tenant.ErrNotFound
	}
	if s.bucketKeys == nil {
		s.bucketKeys = map[string]tenant.BucketKey{}
	}
	key := k.Tenant + "/" + k.Bucket + "/" + k.Name
	if old, ok := s.bucketKeys[key]; ok {
		k.CreatedAt = old.CreatedAt
	} else {
		k.CreatedAt = time.Now()
	}
	k.UpdatedAt = time.Now()
	s.bucketKeys[key] = k
	return k, nil
}

func (s *Store) openBucketKey(k tenant.BucketKey) (tenant.BucketKey, error) {
	if s.Sealed {
		return tenant.BucketKey{}, tenant.ErrSecretsUnavailable
	}
	if s.Unreadable {
		k.SecretKey, k.Unreadable = "", true
	}
	return k, nil
}

func (s *Store) GetBucketKey(_ context.Context, tenantName, bucket, name string) (tenant.BucketKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.bucketKeys[tenantName+"/"+bucket+"/"+name]
	if !ok {
		return tenant.BucketKey{}, tenant.ErrNotFound
	}
	return s.openBucketKey(k)
}

func (s *Store) ListBucketKeys(_ context.Context, tenantName, bucket string) ([]tenant.BucketKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []tenant.BucketKey
	for _, k := range s.bucketKeys {
		if k.Tenant == tenantName && k.Bucket == bucket {
			k, err := s.openBucketKey(k)
			if err != nil {
				return nil, err
			}
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) SetBucketKeyStatus(_ context.Context, tenantName, bucket, name string, status tenant.Status) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tenantName + "/" + bucket + "/" + name
	k, ok := s.bucketKeys[key]
	if !ok {
		return tenant.ErrNotFound
	}
	k.Status = status
	s.bucketKeys[key] = k
	return nil
}

func (s *Store) DeleteBucketKey(_ context.Context, tenantName, bucket, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.bucketKeys, tenantName+"/"+bucket+"/"+name)
	return nil
}

// --- The bucket store --------------------------------------------------------

// BucketStore is an in-memory tenant.BucketStore: buckets by store name,
// users by access key, policies by name.
type BucketStore struct {
	mu sync.Mutex
	// Buckets is what each bucket was last ensured as.
	Buckets map[string]tenant.BucketSpec
	// Objects counts each bucket's object versions; a test puts some there.
	Objects map[string]int
	// Users is every key's user, by access key.
	Users map[string]tenant.BucketKeySpec
	// Policies is every key policy's name, and the bucket it reaches.
	Policies map[string]string
	// Purged is every bucket emptied before it was removed.
	Purged []string
	// Fail, when set, is returned by every call.
	Fail error
}

func NewBucketStore() *BucketStore {
	return &BucketStore{
		Buckets:  map[string]tenant.BucketSpec{},
		Objects:  map[string]int{},
		Users:    map[string]tenant.BucketKeySpec{},
		Policies: map[string]string{},
	}
}

func (f *BucketStore) EnsureBucket(_ context.Context, b tenant.BucketSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Fail != nil {
		return f.Fail
	}
	f.Buckets[b.Bucket] = b
	return nil
}

func (f *BucketStore) BucketHasObjects(_ context.Context, bucket string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Fail != nil {
		return false, f.Fail
	}
	return f.Objects[bucket] > 0, nil
}

func (f *BucketStore) RemoveBucket(_ context.Context, bucket string, purge bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Fail != nil {
		return f.Fail
	}
	if f.Objects[bucket] > 0 {
		if !purge {
			return tenant.ErrBucketNotEmpty
		}
		f.Purged = append(f.Purged, bucket)
		delete(f.Objects, bucket)
	}
	delete(f.Buckets, bucket)
	return nil
}

func (f *BucketStore) EnsureKey(_ context.Context, k tenant.BucketKeySpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Fail != nil {
		return f.Fail
	}
	f.Users[k.AccessKey] = k
	f.Policies[k.Policy] = k.Bucket
	return nil
}

func (f *BucketStore) RemoveKey(_ context.Context, accessKey, policy string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Fail != nil {
		return f.Fail
	}
	delete(f.Users, accessKey)
	delete(f.Policies, policy)
	return nil
}

// SetFail sets or clears Fail.
func (f *BucketStore) SetFail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Fail = err
}
