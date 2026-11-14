---
title: "Tenant Buckets"
weight: 5
---

# Tenant buckets

**A tenant keeps objects in buckets of its own in the site's bucket store, and each key reaches one
bucket.** A bucket is `<tenant>-<name>` in the store, reached path-style at the endpoint its view
reports. Buckets are declared through the API
([ADR-0026](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/platform-services/0026-object-storage/)).
The service is optional: an API with no bucket store answers `503` on these routes. The
[API Reference](/docs/reference/) has every field; this page is what the fields do not say.

## Quotas

**Every bucket has a hard quota, and quotas are allocated, never overcommitted.** The sum of
`quota_gb` over every tenant's buckets may not pass the store's configured capacity. A create, or
an update that raises a quota, that would pass it is refused with `409`, and the message says how
much is left. Lowering a quota is never refused.

- **The store enforces a quota from its scanner, about a minute behind.** Writes can run past a
  quota for that long. A single object larger than the quota is refused at once.
- **Noncurrent versions count.** In a versioned bucket, overwriting an object keeps the old
  version, and both count against the quota.

## Settings

- **`versioning` off after on is suspended**, not undone: S3 cannot un-version a bucket. Versions
  already written stay until they are deleted or expire.
- **`lifecycle`** expires current objects after `expire_days` and noncurrent versions after
  `noncurrent_expire_days`. 0 is none.
- **`public_read`** lets anyone who reaches the store get an object without a key. It grants
  nothing else: an anonymous caller cannot list the bucket. Whether a network reaches the store at
  all is the site's routing policy, not this setting.

## Keys

**A key is a store user whose policy reaches its one bucket and nothing else.** `write` lists, gets,
puts and deletes objects and their versions; `read` lists and gets them.

- **Every bucket is created with a `default` key** with `write` access, returned in the bucket's
  create response. It can be deleted like any other.
- **The API chooses `access_key` and `secret_key`.** The secret is returned in the create response
  only; the tenant's own state is the copy it uses. The API keeps a sealed copy so it can make the
  user again after the store is rebuilt.
- **A key name is unique within its bucket**, and a second create of the same name is `409`.

## Retries

**A create that failed at the store answers `502` with what was made, and calling it again resumes
it with the same key.** The rows are written before the store is called, so a retry never mints a
second credential.

## Delete

**A bucket that holds anything is refused without `force`.** Any object version or delete marker
counts. `DELETE ...?force=true` removes every version and delete marker, then the bucket, its keys
and their policies. The substrate keeps no copy: a bucket's contents are not backed up.

**Removing the tenant removes its buckets with everything in them**, and their keys. A reconcile
makes every bucket and key again in a rebuilt store, empty.
