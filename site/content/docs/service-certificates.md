---
title: "Service Certificates"
weight: 5
---

# Service certificates

**A tenant's own service gets a server certificate from the API, for a name in the tenant's own
zone, and the tenant keeps the key.** The site's Tenant Service CA signs it
([ADR-0037](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/substrate/0037-tenant-service-certificates/)).
It chains to the Deevnet Root CA, which every client on a site already trusts. The
[API Reference](/docs/reference/) has every field; this page is what the fields do not say.

## The key

**The private key never reaches the API.** A tenant makes it, keeps it, and sends a signing request
made with it. The certificate comes back; the key was never sent.

- **The request must be signed by its own key.** That is what shows the sender holds it.
- **The key is RSA of 2048 bits or more, or ECDSA P-256.** Anything else is a `400`.
- **Nothing in the answer is secret.** A certificate is what a server hands to whoever connects, so
  a read returns exactly what the issue returned.

## What is taken from a request

**The request is read for its public key, and for nothing else.** Its subject, its names and its
extensions are not used
([Certificates standard](https://deevnet.github.io/deevnet-docs/docs/standards/certificates/) 4.6).

A request that names `grafana.mobile.deevnet.net` gets a certificate for the name in the path, in
the caller's zone, and no error: what a request says about itself was never part of the question.
The body takes two fields, the request and further labels, and an unknown field is a `400`. There
is no lifetime to ask for and no usage to choose.

## Names

**A tenant sends labels, never names.** The certificate `console` for the tenant `eds` at the site
`mobile` is for `console.eds.mobile.deevnet.net`, because the API appends the zone, as it does for
a published name or a workload.

- **The path's label is the certificate's own**, and its common name.
- **`names` adds further labels** in the same zone, up to seven. Each becomes a DNS name beside the
  first.
- **A label is one DNS label.** A dot, a wildcard, an address, or a name with a zone in it is a
  `400`. There is no way to spell a name outside the tenant's zone, because a tenant never spells a
  zone.
- **A label need not be published first.** A tenant may publish names with its own DNS update key,
  which the API does not see. The zone is the boundary, not the API's list of names.

## What a certificate says

| | |
|---|---|
| Subject | `O=Deevnet, OU=<Site> Tenant Services, CN=<label>.<tenant>.<site>.deevnet.net` |
| Names | DNS only |
| Lifetime | one year |
| Usage | server authentication only |

**It is the same for every tenant.** The tenant is in the name, not the OU.

**`ca_chain` is what a server presents after the leaf:** the Tenant Service CA, then the Site CA.
Never the root: a client holds it, and builds the chain from those two.

## Asking again

**Issuing is an ensure.** A tenant's apply sends the same request every time.

- **The same key and the same names return the same certificate**, with `200`, while more than
  sixty days remain before it expires.
- **A new key, a changed name, or fewer than sixty days, issues another**, with `201`.
  `renew_after` is the day that begins.
- **The same key is told by the key**, not by the request's bytes. A request made again for one key
  is the same question.
- **One certificate is held per name**: the one current for it. A tenant holds at most 64.

**Nothing renews a certificate for a tenant that does not ask.** One that applies its configuration
inside the sixty days renews; one that applies nothing for a year serves an expired certificate.

## Revocation

**There is none.** Deleting a certificate makes the API forget it. Reissuing replaces it. Neither
withdraws the one before, which stays valid until it expires wherever its key still is. A tenant
that has lost a key makes a new one and asks again; the old certificate is not undone.

## What the API checks, and what the secret store checks

**Two things stand between a request and a certificate for a name that is not the tenant's, and
they do not share a fault.**

- **The API builds every name inside the caller's zone**, and reads the certificate that comes back
  before returning it: its key, its names, its usage and its lifetime must be what was asked for.
  One that says more is refused, and answers `502`.
- **The secret store's signing role permits only names at least two labels below the site's zone.**
  A tenant's name always is; a substrate name never is. It ignores the request's own names as well.

The API may sign on that one role. It cannot read the CA's key, change the role or use another.

## A site with no Tenant Service CA

**The routes refuse with a reason.** `OPENBAO_TENANT_SERVICE_MOUNT` turns certificates on
([Configuration](/docs/configuration/#service-certificates)); a site that has not held the CA's
ceremony leaves it unset.
