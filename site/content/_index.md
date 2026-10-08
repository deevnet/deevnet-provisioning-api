---
title: "Deevnet API"
type: docs
---

<div class="landing-hero">

# Deevnet API

<p class="subtitle">Provisioning API, {{< param version >}}</p>

</div>

The Deevnet API builds tenants on a [Deevnet](https://deevnet.github.io/deevnet-docs/) site: their
network, DNS zone and state-store credential, their workloads and published names, and the Wi-Fi
keys, registry entries, fixed addresses and MQTT broker accounts their devices need.

It is **provisioning-only**. Nothing at runtime depends on it being up: devices, the broker, the
access point and tenant workloads all keep working without it.

Most callers never speak to it directly. A tenant declares what it wants in Terraform, and the
[`deevnet/deevnet` provider](https://deevnet.github.io/terraform-provider-deevnet/) makes the calls.

<div class="section-cards">
<a class="section-card" href="docs/reference/">
<h3>API Reference</h3>
<p>Every route, request and response, rendered from the OpenAPI specification.</p>
</a>
<a class="section-card" href="docs/authentication/">
<h3>Authentication</h3>
<p>The four kinds of token and what each may call.</p>
</a>
<a class="section-card" href="docs/tenant-lifecycle/">
<h3>Tenant Lifecycle</h3>
<p>Admit, create, restore, resume, reconcile and delete.</p>
</a>
<a class="section-card" href="docs/device-services/">
<h3>Device Services</h3>
<p>Registry, fixed addresses, Wi-Fi keys and broker accounts.</p>
</a>
<a class="section-card" href="docs/conventions/">
<h3>Conventions</h3>
<p>Ensures, partial objects, where secrets appear, and errors.</p>
</a>
<a class="section-card" href="docs/configuration/">
<h3>Configuration</h3>
<p>Every environment variable the service reads.</p>
</a>
</div>

## A first call

```bash
curl --cacert deevnet-root-ca.pem \
     -H "Authorization: Bearer $DEEVNET_API_TOKEN" \
     "$DEEVNET_API_ENDPOINT/v1/tenants/tdemo"
```

The specification is one file,
[openapi.yaml](https://github.com/deevnet/deevnet-provisioning-api/blob/main/api/openapi.yaml)
(OpenAPI 3.1). A test in the repository fails when it and the service disagree on a route or a
field.
