package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/backend/minio"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Buckets on the Pi (CHG-0073) are Deevnet's (ADR-0026, CHG-0069): silo, the
// store that serves Deevnet's buckets, run on the card, and made through the
// API's own bucket code (internal/backend/minio) with the API's own rules
// (internal/tenant). A bucket is "<tenant>-<name>", path-style; each key
// reaches one bucket, read or write; a bucket has a quota, versioning,
// expiry and anonymous read, as on Deevnet.
//
// The store runs only once a bucket exists: an owner without buckets pays no
// memory for it.

const (
	s3Port = 9000
	// The image's silo unit, disabled until the first bucket.
	siloUnit = "silo"
	// The data directory, whose filesystem the quotas must fit.
	siloData = "/var/lib/silo"
	// What the card keeps free beyond the quotas.
	siloReserveGB = 1
)

// bucketFile is one bucket and its keys, as the card keeps them.
type bucketFile struct {
	Name                 string               `json:"name"`
	QuotaGB              int                  `json:"quota_gb"`
	Versioning           bool                 `json:"versioning"`
	ExpireDays           int                  `json:"expire_days,omitempty"`
	NoncurrentExpireDays int                  `json:"noncurrent_expire_days,omitempty"`
	PublicRead           bool                 `json:"public_read,omitempty"`
	Keys                 map[string]bucketKey `json:"keys"`
}

type bucketKey struct {
	Access    string `json:"access"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

func (k *kit) bucketsDir() string            { return filepath.Join(k.etc(), "buckets") }
func (k *kit) bucketPath(name string) string { return filepath.Join(k.bucketsDir(), name+".json") }
func (k *kit) siloEnv() string               { return filepath.Join(k.etc(), "silo.env") }
func (k *kit) siloCertsDir() string          { return filepath.Join(k.etc(), "silo-certs") }

// bucketStore is what the bucket commands drive: the API's own client against
// the card's silo. A variable, so a test can drive a fake.
var bucketStore = func(k *kit, st state) (tenant.BucketStore, error) {
	return minio.NewBuckets(fmt.Sprintf("%s:%d", st.name("s3"), s3Port), st.SiloRootUser, st.SiloRootPassword, k.caFile())
}

func (k *kit) cmdBucket(w io.Writer, args []string) error {
	const usage = "bucket add NAME --quota-gb N [...] | bucket list | bucket rm NAME [--force] | bucket key add|list|rm ..."
	if len(args) == 0 {
		return errors.New(usage)
	}
	st, err := k.loadState()
	if err != nil {
		return err
	}
	switch args[0] {
	case "add":
		return k.bucketAdd(w, st, args[1:])
	case "list":
		return k.bucketList(w, st)
	case "rm":
		return k.bucketRm(w, st, args[1:])
	case "key":
		if len(args) < 2 {
			return errors.New("bucket key add BUCKET KEY --access read|write [--key-file F] | bucket key list BUCKET | bucket key rm BUCKET KEY")
		}
		switch args[1] {
		case "add":
			return k.bucketKeyAdd(w, st, args[2:])
		case "list":
			return k.bucketKeyList(w, st, args[2:])
		case "rm":
			return k.bucketKeyRm(w, st, args[2:])
		}
	}
	return errors.New(usage)
}

// splitName takes the NAME before the flags, as `export DIR --app` does.
func splitName(args []string, n int, what string) ([]string, []string, error) {
	if len(args) < n {
		return nil, nil, fmt.Errorf("%s", what)
	}
	for _, a := range args[:n] {
		if strings.HasPrefix(a, "-") {
			return nil, nil, fmt.Errorf("%s", what)
		}
	}
	return args[:n], args[n:], nil
}

func (k *kit) bucketAdd(w io.Writer, st state, args []string) error {
	names, rest, err := splitName(args, 1, "bucket add NAME --quota-gb N [--versioning] [--expire-days N] [--noncurrent-expire-days N] [--public-read] [--key-file FILE]")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("bucket add", flag.ContinueOnError)
	quota := fs.Int("quota-gb", 0, "the most the bucket holds, every version counted")
	versioning := fs.Bool("versioning", false, "keep old versions of each object")
	expire := fs.Int("expire-days", 0, "expire current objects after this many days (0: never)")
	noncurrent := fs.Int("noncurrent-expire-days", 0, "expire old versions after this many days (0: never)")
	public := fs.Bool("public-read", false, "objects readable with no key, on this Pi's network")
	keyFile := fs.String("key-file", "", "the default key's access_key and secret_key, as JSON, to keep the key the app has")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	req := tenant.BucketRequest{Name: names[0], QuotaGB: *quota, Versioning: *versioning,
		ExpireDays: *expire, NoncurrentExpireDays: *noncurrent, PublicRead: *public}
	if err := tenant.ValidateBucket(st.Tenant, req); err != nil {
		return err
	}
	if _, err := os.Stat(k.bucketPath(req.Name)); err == nil {
		return tenant.ErrBucketExists
	}
	key, err := keyFrom(*keyFile)
	if err != nil {
		return err
	}
	key.Access = tenant.BucketAccessWrite
	if err := k.checkCapacity(req.QuotaGB); err != nil {
		return err
	}
	st, err = k.ensureSilo(st)
	if err != nil {
		return err
	}
	store, err := bucketStore(k, st)
	if err != nil {
		return err
	}
	b := bucketFile{Name: req.Name, QuotaGB: req.QuotaGB, Versioning: req.Versioning, ExpireDays: req.ExpireDays,
		NoncurrentExpireDays: req.NoncurrentExpireDays, PublicRead: req.PublicRead,
		Keys: map[string]bucketKey{tenant.DefaultBucketKey: key}}
	ctx := context.Background()
	if err := store.EnsureBucket(ctx, bucketSpecOf(st, b)); err != nil {
		return fmt.Errorf("making the bucket: %w", err)
	}
	if err := store.EnsureKey(ctx, keySpecOf(st, b.Name, tenant.DefaultBucketKey, key)); err != nil {
		return fmt.Errorf("making its key: %w", err)
	}
	if err := k.saveBucket(b); err != nil {
		return err
	}
	fmt.Fprintf(w, "bucket %s, %d GB; key %q (write): %s\n", tenant.BucketStoreName(st.Tenant, b.Name), b.QuotaGB, tenant.DefaultBucketKey, key.AccessKey)
	fmt.Fprintf(w, "export it to an app: sudo deevnet-kit export DIR --bucket %s:%s\n", b.Name, tenant.DefaultBucketKey)
	return nil
}

func (k *kit) bucketList(w io.Writer, st state) error {
	bs, err := k.loadBuckets()
	if err != nil {
		return err
	}
	if len(bs) == 0 {
		fmt.Fprintln(w, "no buckets; deevnet-kit bucket add NAME --quota-gb N")
		return nil
	}
	for _, b := range bs {
		var flags []string
		if b.Versioning {
			flags = append(flags, "versioned")
		}
		if b.PublicRead {
			flags = append(flags, "public read")
		}
		fmt.Fprintf(w, "%-32s %4d GB  %d key(s)  %s\n", tenant.BucketStoreName(st.Tenant, b.Name), b.QuotaGB, len(b.Keys), strings.Join(flags, ", "))
	}
	return nil
}

func (k *kit) bucketRm(w io.Writer, st state, args []string) error {
	names, rest, err := splitName(args, 1, "bucket rm NAME [--force]")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("bucket rm", flag.ContinueOnError)
	force := fs.Bool("force", false, "remove it and everything in it")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	b, err := k.loadBucket(names[0])
	if err != nil {
		return err
	}
	store, err := bucketStore(k, st)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if err := store.RemoveBucket(ctx, tenant.BucketStoreName(st.Tenant, b.Name), *force); err != nil {
		if errors.Is(err, tenant.ErrBucketNotEmpty) {
			return fmt.Errorf("%s is not empty: bucket rm %s --force removes it and everything in it: %w",
				tenant.BucketStoreName(st.Tenant, b.Name), b.Name, err)
		}
		return err
	}
	for name, key := range b.Keys {
		if err := store.RemoveKey(ctx, key.AccessKey, tenant.BucketKeyPolicyName(tenant.BucketStoreName(st.Tenant, b.Name), name)); err != nil {
			return err
		}
	}
	if err := os.Remove(k.bucketPath(b.Name)); err != nil {
		return err
	}
	fmt.Fprintf(w, "removed %s and its keys\n", tenant.BucketStoreName(st.Tenant, b.Name))
	return nil
}

func (k *kit) bucketKeyAdd(w io.Writer, st state, args []string) error {
	names, rest, err := splitName(args, 2, "bucket key add BUCKET KEY --access read|write [--key-file FILE]")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("bucket key add", flag.ContinueOnError)
	access := fs.String("access", "", "read or write")
	keyFile := fs.String("key-file", "", "an access_key and secret_key, as JSON, to keep the key the app has")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	b, err := k.loadBucket(names[0])
	if err != nil {
		return err
	}
	name := names[1]
	if !tenant.ValidBucketKeyName(name) {
		return errors.New("key name must be 1-20 lowercase alphanumerics or dashes, starting with a letter")
	}
	if !tenant.ValidBucketAccess(*access) {
		return fmt.Errorf("--access must be %q or %q", tenant.BucketAccessRead, tenant.BucketAccessWrite)
	}
	if _, ok := b.Keys[name]; ok {
		return tenant.ErrBucketKeyExists
	}
	key, err := keyFrom(*keyFile)
	if err != nil {
		return err
	}
	key.Access = *access
	store, err := bucketStore(k, st)
	if err != nil {
		return err
	}
	if err := store.EnsureKey(context.Background(), keySpecOf(st, b.Name, name, key)); err != nil {
		return fmt.Errorf("making the key: %w", err)
	}
	b.Keys[name] = key
	if err := k.saveBucket(b); err != nil {
		return err
	}
	fmt.Fprintf(w, "key %q (%s) to %s: %s\n", name, key.Access, tenant.BucketStoreName(st.Tenant, b.Name), key.AccessKey)
	return nil
}

func (k *kit) bucketKeyList(w io.Writer, st state, args []string) error {
	if len(args) != 1 {
		return errors.New("bucket key list BUCKET")
	}
	b, err := k.loadBucket(args[0])
	if err != nil {
		return err
	}
	names := make([]string, 0, len(b.Keys))
	for n := range b.Keys {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "%-20s %-5s %s\n", n, b.Keys[n].Access, b.Keys[n].AccessKey)
	}
	return nil
}

func (k *kit) bucketKeyRm(w io.Writer, st state, args []string) error {
	if len(args) != 2 {
		return errors.New("bucket key rm BUCKET KEY")
	}
	b, err := k.loadBucket(args[0])
	if err != nil {
		return err
	}
	key, ok := b.Keys[args[1]]
	if !ok {
		return tenant.ErrBucketKeyNotFound
	}
	store, err := bucketStore(k, st)
	if err != nil {
		return err
	}
	if err := store.RemoveKey(context.Background(), key.AccessKey,
		tenant.BucketKeyPolicyName(tenant.BucketStoreName(st.Tenant, b.Name), args[1])); err != nil {
		return err
	}
	delete(b.Keys, args[1])
	if err := k.saveBucket(b); err != nil {
		return err
	}
	fmt.Fprintf(w, "removed key %q from %s\n", args[1], tenant.BucketStoreName(st.Tenant, b.Name))
	return nil
}

// keyFrom reads a key to adopt, in the shape tdemo's files_bucket output gives
// a key ({"access_key": ..., "secret_key": ...}), or mints one as the API does.
func keyFrom(path string) (bucketKey, error) {
	if path == "" {
		a, s, err := tenant.NewBucketCredentials()
		return bucketKey{AccessKey: a, SecretKey: s}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return bucketKey{}, err
	}
	defer f.Close()
	var in struct {
		AccessKey string `json:"access_key"`
		SecretKey string `json:"secret_key"`
	}
	if err := json.NewDecoder(f).Decode(&in); err != nil {
		return bucketKey{}, fmt.Errorf("%s: %w", path, err)
	}
	// The store's own limits on a user: an access key of 3 or more, a
	// secret of 8 to 40.
	if len(in.AccessKey) < 3 || len(in.SecretKey) < 8 || len(in.SecretKey) > 40 {
		return bucketKey{}, fmt.Errorf("%s: need an access_key and a secret_key of 8 to 40 characters", path)
	}
	return bucketKey{AccessKey: in.AccessKey, SecretKey: in.SecretKey}, nil
}

func bucketSpecOf(st state, b bucketFile) tenant.BucketSpec {
	return tenant.BucketSpec{Bucket: tenant.BucketStoreName(st.Tenant, b.Name), QuotaGB: b.QuotaGB, Versioning: b.Versioning,
		ExpireDays: b.ExpireDays, NoncurrentExpireDays: b.NoncurrentExpireDays, PublicRead: b.PublicRead}
}

func keySpecOf(st state, bucket, name string, key bucketKey) tenant.BucketKeySpec {
	sb := tenant.BucketStoreName(st.Tenant, bucket)
	return tenant.BucketKeySpec{Bucket: sb, Policy: tenant.BucketKeyPolicyName(sb, name),
		AccessKey: key.AccessKey, SecretKey: key.SecretKey, Access: key.Access}
}

func (k *kit) saveBucket(b bucketFile) error {
	if err := os.MkdirAll(k.bucketsDir(), 0o700); err != nil {
		return err
	}
	return writeJSON(k.bucketPath(b.Name), b, 0o600)
}

func (k *kit) loadBucket(name string) (bucketFile, error) {
	var b bucketFile
	body, err := os.ReadFile(k.bucketPath(name))
	if errors.Is(err, os.ErrNotExist) {
		return b, tenant.ErrBucketNotFound
	}
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return b, fmt.Errorf("%s: %w", k.bucketPath(name), err)
	}
	if b.Keys == nil {
		b.Keys = map[string]bucketKey{}
	}
	return b, nil
}

func (k *kit) loadBuckets() ([]bucketFile, error) {
	ents, err := os.ReadDir(k.bucketsDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []bucketFile
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := k.loadBucket(strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// checkCapacity stands in for Deevnet's admission: the quotas, with the new
// one, must fit the card's free space and a reserve.
var checkCapacityStat = func(path string) (freeGB int, err error) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return 0, err
	}
	return int(fs.Bavail * uint64(fs.Bsize) >> 30), nil
}

func (k *kit) checkCapacity(addGB int) error {
	bs, err := k.loadBuckets()
	if err != nil {
		return err
	}
	used := addGB
	for _, b := range bs {
		used += b.QuotaGB
	}
	dir := k.p(siloData)
	if _, err := os.Stat(dir); err != nil {
		dir = k.p("/")
	}
	free, err := checkCapacityStat(dir)
	if err != nil {
		return err
	}
	if used+siloReserveGB > free {
		return &tenant.CapacityError{RequestedGB: addGB, FreeGB: max(free-siloReserveGB-(used-addGB), 0), CapacityGB: max(free-siloReserveGB, 0)}
	}
	return nil
}

// ensureSilo mints the store's root login on the first bucket, points silo at
// the card's certificate, and starts it.
func (k *kit) ensureSilo(st state) (state, error) {
	if st.SiloRootUser == "" {
		var err error
		if st.SiloRootUser, err = randomHex(10); err != nil {
			return st, err
		}
		if st.SiloRootPassword, err = randomHex(20); err != nil {
			return st, err
		}
		if err := writeJSON(k.stateFile(), st, 0o600); err != nil {
			return st, err
		}
	}
	env := fmt.Sprintf("# deevnet-kit - generated; silo's root login and settings\nMINIO_ROOT_USER=%s\nMINIO_ROOT_PASSWORD=%s\nMINIO_BROWSER=off\n",
		st.SiloRootUser, st.SiloRootPassword)
	if err := writeFile(k.siloEnv(), []byte(env), 0o600); err != nil {
		return st, err
	}
	// silo reads public.crt and private.key from its certs directory.
	if err := os.MkdirAll(k.siloCertsDir(), 0o755); err != nil {
		return st, err
	}
	for link, target := range map[string]string{"public.crt": "/etc/deevnet-kit/tls/server.pem", "private.key": "/etc/deevnet-kit/tls/server-key.pem"} {
		p := filepath.Join(k.siloCertsDir(), link)
		if cur, err := os.Readlink(p); err == nil && cur == target {
			continue
		}
		_ = os.Remove(p)
		if err := os.Symlink(target, p); err != nil {
			return st, err
		}
	}
	if k.noExec {
		return st, nil
	}
	if err := runCmd("systemctl", "enable", "--now", siloUnit); err != nil {
		return st, err
	}
	return st, waitSilo(fmt.Sprintf("https://%s:%d", st.name("s3"), s3Port), k.caFile(), time.Minute)
}

func waitSilo(base, caFile string, within time.Duration) error {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	deadline := time.Now().Add(within)
	for {
		resp, err := hc.Get(base + "/minio/health/live")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the bucket store did not answer at %s within %s", base, within)
		}
		time.Sleep(2 * time.Second)
	}
}

// bucketEnv is kit.env's bucket lines for the keys --bucket named: the
// store, and each bucket's name and key, under names the app reads.
func (k *kit) bucketEnv(st state, h string, picks []string) (string, error) {
	if len(picks) == 0 {
		return "", nil
	}
	var out strings.Builder
	for _, p := range picks {
		name, keyName, ok := strings.Cut(p, ":")
		if !ok {
			keyName = tenant.DefaultBucketKey
		}
		b, err := k.loadBucket(name)
		if err != nil {
			return "", fmt.Errorf("--bucket %s: %w", p, err)
		}
		key, ok := b.Keys[keyName]
		if !ok {
			return "", fmt.Errorf("--bucket %s: %w", p, tenant.ErrBucketKeyNotFound)
		}
		v := "BUCKET_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		fmt.Fprintf(&out, "%s=%s\n%s_ACCESS_KEY=%s\n%s_SECRET_KEY=%s\n", v, tenant.BucketStoreName(st.Tenant, name), v, key.AccessKey, v, key.SecretKey)
	}
	return out.String(), nil
}

// s3Env is kit.env's store lines, the names tdemo's kit_env uses.
func s3Env(st state, h, caName string) string {
	return fmt.Sprintf("S3_ENDPOINT=https://%s:%s\nS3_CA_FILE=%s\n", st.appHost("s3", h), strconv.Itoa(s3Port), caName)
}
