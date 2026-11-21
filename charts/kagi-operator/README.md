# kagi-operator

Kubernetes operator for [Kagi](https://kagi.pw) — syncs secrets and TLS
certificates from Kagi into native Kubernetes `Secret`s (`KagiSecret`,
`KagiCertificate` CRDs), and can inject a secretless-delivery init container
into annotated application pods via a mutating admission webhook so workloads
never need a long-lived credential mounted at all.

This chart is **generalized and public** — it targets any cluster, not
Korur's own. Korur's internal, ArgoCD-managed deployment lives at
`gitops/platform/stormcloud/kagi-operator` in the monorepo and is a
**separate, hand-maintained chart**; this one does not replace or affect it.

## Installing

```sh
helm install kagi-operator oci://ghcr.io/korurlabs/charts/kagi-operator \
  --version 0.4.0 \
  --namespace kagi-operator-system --create-namespace \
  --set auth.existingSecret=kagi-operator-token
```

`auth.existingSecret` must name a `Secret` (in the same namespace, or see
`auth.namespace`) with a key named `KAGI_TOKEN` or `token` (or, if you set
`auth.existingSecretKey`, exactly that key) holding a Kagi Personal Access
Token:

```sh
kubectl create secret generic kagi-operator-token \
  -n kagi-operator-system \
  --from-literal=token=<your Kagi PAT>
```

For a quick local/dev test only, you can skip the pre-created Secret and pass
the token directly (it ends up in the Helm release's stored values, so avoid
this outside a throwaway cluster):

```sh
helm install kagi-operator oci://ghcr.io/korurlabs/charts/kagi-operator \
  --version 0.4.0 \
  -n kagi-operator-system --create-namespace \
  --set auth.token=<your Kagi PAT>
```

## Values

| Key | Default | Description |
|---|---|---|
| `replicaCount` | `1` | Operator replicas. Requires `leaderElection.enabled=true` above 1. |
| `image.repository` | `ghcr.io/korurlabs/kagi-operator` | Operator image. |
| `image.tag` | `""` | Falls back to `.Chart.AppVersion`. |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |
| `nameOverride` / `fullnameOverride` | `""` | |
| `kagiApiUrl` | `https://api.kagi.pw` | Only change for self-hosted Kagi (ENTERPRISE plan). |
| `maxConcurrentReconciles` | `4` | Parallel `KagiSecret` reconciles. |
| `leaderElection.enabled` | `false` | Turn on before scaling `replicaCount` above 1. |
| `resources` | `128Mi/500m limit, 64Mi/10m request` | |
| `nodeSelector` / `tolerations` / `affinity` | `{}` / `[]` / `{}` | Deliberately empty — not coupled to any cluster's node pools. |
| `podAnnotations` / `podLabels` | `{}` | |
| `serviceAccount.create` | `true` | |
| `serviceAccount.annotations` | `{}` | e.g. for Azure Workload Identity / IRSA-style annotations if you front the PAT with one of those instead (see Auth below). |
| `serviceAccount.name` | `""` | |
| `rbac.create` | `true` | ClusterRole/ClusterRoleBinding + namespaced leader-election Role/RoleBinding + (conditionally) metrics-auth ClusterRole/ClusterRoleBinding. |
| `auth.mode` | `token-secret` | `token-secret` (PAT) or `exchange` (projected ServiceAccount token, no PAT). See Auth below. |
| `auth.exchange.audience` | `api.kagi.pw` | Audience of the projected token under `exchange`: the Kagi API host. |
| `auth.exchange.expirationSeconds` | `3600` | Lifetime of the projected token under `exchange`. |
| `auth.existingSecret` | `""` | Name of a Secret you create yourself holding the PAT. **Recommended.** |
| `auth.existingSecretKey` | `""` | Key within that Secret. Empty accepts either `KAGI_TOKEN` or `token`; set it only for a custom key, which the operator then requires exclusively. |
| `auth.token` | `""` | Raw PAT the chart wraps into a Secret. Dev convenience only. |
| `auth.namespace` | `""` | Namespace of the token Secret. Defaults to the release namespace. |
| `crds.install` | `true` | See CRDs section below. |
| `crds.keep` | `true` | Stamps `helm.sh/resource-policy: keep` so `helm uninstall` never deletes the CRDs (or your custom resources). |
| `injection.enabled` | `true` | The pod-injection mutating admission webhook. See Injection below. |
| `injection.kagiInitImage` | `""` | Advanced override — leave empty; see Injection below. |
| `injection.saTokenAudience` | `api.kagi.pw` | Default projected-token audience. |
| `injection.failurePolicy` | `Fail` | Safe because `objectSelector` already keeps unlabeled pods away. |
| `injection.containerPort` | `9443` | |
| `injection.existingCertSecret` | `""` | Opt-in escape hatch — use your own TLS Secret instead of an operator-issued certificate. Only for private-CA mandates; see Webhook TLS below. |
| `metrics.enabled` | `true` | |
| `metrics.secure` | `true` | HTTPS + authn/authz metrics endpoint. |
| `metrics.service.port` | `8443` | |
| `extraEnv` / `extraArgs` | `[]` | Escape hatches for anything not otherwise exposed. |

## What RBAC this chart grants

`rbac.create` (default `true`) creates a `ClusterRole` for the operator. Two
grants in it are worth knowing about before you install, rather than
discovering later:

- **Cluster-wide CRUD on `Secrets`.** This is inherent to what the operator
  does: `KagiSecret` and `KagiCertificate` in `Secret` delivery mode write the
  synced material into a `Secret` in whatever namespace the custom resource
  names, so the permission cannot be namespace-scoped without breaking the
  product. It predates the webhook work and is not related to webhook TLS. If
  that is unacceptable in your cluster, use injection (`kagi.pw/inject`) rather
  than `mode: Secret`, which never persists a secret value at all.
- **`list`/`watch` on `MutatingWebhookConfigurations`, cluster-wide, plus
  `get`/`update` restricted by `resourceNames` to the operator's own object.**
  The write verbs are deliberately scoped: cluster-wide `update` on that
  resource would let anyone who can run a pod in the operator's namespace mount
  its ServiceAccount token and rewrite any webhook in the cluster. `list` and
  `watch` cannot take `resourceNames` — the informer needs the collection — so
  they stay cluster-wide and read-only. Both rules are gated on
  `injection.enabled`: with injection off no `MutatingWebhookConfiguration`
  exists and the operator never touches one, so neither rule is rendered.

## Auth

`auth.mode` sets the operator's `--kagi-auth` flag.

- `token-secret` (default): a static **Personal Access Token**, wired via
  `--default-token-secret` / `--default-token-namespace` from
  `auth.existingSecret` / `auth.token`. Every existing install keeps this mode.
- `exchange`: no PAT in the cluster. The chart mounts a projected
  ServiceAccount token (audience `auth.exchange.audience`, default
  `api.kagi.pw`) at `/var/run/secrets/kagi/token`, and the operator exchanges it
  at `POST /kagi/auth/token` for a short-lived token per (app, environment)
  pair. In the portal, under Integrations, connect the cluster and give it a
  workload role whose Kubernetes rule trusts the release namespace and the
  operator's ServiceAccount, scoped to the pairs your `KagiSecret`s read. The
  operator names no role: the admin's roles decide what it gets.

Under `exchange`, a `KagiSecret` needs `spec.appId` (a `spec.folderPath` cannot
be resolved before a credential exists) and a `KagiCertificate` needs its own
`spec.tokenSecret`; otherwise the object reports `Ready=False` with reason
`WorkloadTokenCannotResolve` and waits for a spec change. A pair no role grants
reports `WorkloadAccessDenied` and is retried with back-off. `kagiApiUrl` must be
the public API host, because the exchange checks each resource against it.

In both modes, individual `KagiSecret` / `KagiCertificate` objects may name
their own `spec.tokenSecret` to override the default per object.

## Injection (secretless workload-identity delivery)

When `injection.enabled` (default `true`), the chart installs:

- a webhook `Service` fronting the manager's admission HTTPS server,
- a `MutatingWebhookConfiguration` scoped by `objectSelector` to pods labeled
  `kagi.pw/inject: "true"` — **unlabeled pods are never sent to it**, so
  `failurePolicy: Fail` never puts unrelated cluster-wide pod admission at
  risk.

The webhook's TLS serving certificate is **not** part of the chart — the
operator issues and rotates it itself (see below). There are no prerequisites.

To opt an application pod in, label its pod template and set the required
annotations:

```yaml
metadata:
  labels:
    kagi.pw/inject: "true"
  annotations:
    kagi.pw/app-id: "00000000-0000-0000-0000-0000000000aa"
    kagi.pw/environment: production
spec:
  containers:
    - name: app
      command: ["/app/server"]   # required — the webhook can't read the image ENTRYPOINT
```

The webhook injects an init container that stages the static `kagi-init`
binary onto a memory-backed (`tmpfs`) volume, mounts a short-lived projected
ServiceAccount token, and rewrites the target container's command to run
through `kagi-init`. At runtime `kagi-init` exchanges the SA token for a
scoped Kagi token, fetches the app's secrets, and `exec`s the original
command with the merged environment — no secret value, and no long-lived
credential, is ever persisted in the cluster.

### `kagi-init` is NOT a separate image

`kagi-init` ships **bundled inside the operator image** (`/kagi-init`,
built as a second Go binary in the same `Dockerfile` as `/manager`). There is
no `ghcr.io/korurlabs/kagi-init` image published today. By default the
operator resolves the injected init-container image to **its own running
image** at startup (via the Downward API `POD_NAME`/`POD_NAMESPACE` this
chart always sets when injection is enabled) — leave `injection.kagiInitImage`
empty. Only set it if a future release starts publishing `kagi-init`
standalone; if it ever does, the release CI must build+push that second
image too, and this chart's `Chart.yaml` `artifacthub.io/images` annotation
must gain a matching entry.

### Webhook TLS is handled automatically

**There is nothing to install, configure or renew.** cert-manager is *not*
required, and is no longer used at all.

On startup the operator issues its own serving certificate: it creates the
`Secret` `kagi-operator-webhook-server-cert` in its own namespace if
absent, mints a CA plus a leaf certificate with SANs
`<svc>.<ns>.svc` / `<svc>.<ns>.svc.cluster.local`, and patches the CA onto the
`MutatingWebhookConfiguration`'s `caBundle`. It re-checks on a timer and
rotates well ahead of expiry, re-publishing the `caBundle` each time. The
`Secret` is the shared source of truth, so multiple replicas converge instead
of fighting.

(Names on this page assume the documented `helm install kagi-operator ...`.
Every object is named after the Helm fullname — the release name itself when it
already contains `kagi-operator`, otherwise `<release>-kagi-operator` — so
`helm install foo` yields `foo-kagi-operator-webhook-server-cert` instead.)

The operator also re-checks that Secret every 5 minutes. If it no longer holds
exactly the material the operator issued — an extra CA appended to `ca.crt`, say,
or a `ca.crt` that no longer matches the `ca.key` beside it — it records a
`WebhookCertificateTampered` Warning Event on the `MutatingWebhookConfiguration`
and re-mints its CA, restoring a clean trust anchor without an outage. The same
checks run at the readiness gate, so a replica whose `Secret` has been poisoned
stays out of the webhook `Service` until it is repaired. The monitor deliberately
does **not** stop serving on detection: dropping out of the Service while a
poisoned `caBundle` stayed published would hand the admission traffic to whoever
poisoned it.

**Alert on a *repeating* `WebhookCertificateTampered` Event.** Because repair is
automatic and non-disruptive, an attacker who rewrites `ca.key` after every
repair produces no outage at all — just one Warning Event per check interval,
indefinitely. A single Event can be an upgrade artifact or a stale hand-edit; the
same Event recurring means **something is actively writing to the cert `Secret`
right now**, not that a flag is stuck. Treat it as an intrusion signal and go
look at who has write access, rather than silencing it.

> **This catches *partial* tampering — it is not a defence against a coherent
> replacement.** Write access to that `Secret` is equivalent to admission control
> over every injected pod. This is inherent to the pattern (Gatekeeper and Istio
> share it) and is the same boundary described under `existingCertSecret` below.
> Someone who can write the `Secret` can supply a fully self-consistent `ca.crt`,
> `ca.key`, `tls.crt` and `tls.key` that passes every check here and publishes
> their own root — `ca.key` lives in the same `Secret`, so it is replaced right
> alongside `ca.crt`. What the checks do catch is an appended anchor, a swapped
> field, a cross-signature, an expired or wrong-SAN leaf, and honest
> misconfiguration. **RBAC on this `Secret` is the actual control**, on the
> default path just as much as on the bring-your-own one.

The webhook handler is not registered until the `caBundle` the API server will
use actually matches the certificate the operator serves, so the operator never
serves on a certificate the API server would reject. If that never converges
(most likely cause: the `MutatingWebhookConfiguration` was renamed out from
under the operator), the operator exits with an explicit error rather than
running in a broken state.

This replaces two earlier paths, both removed:

- **cert-manager** — an undeclared hard dependency. `helm install` failed on
  clusters without it, and the released `install.yaml` only *partially*
  applied, leaving a `failurePolicy: Fail` webhook with an empty `caBundle`
  and no operator running — which made every pod labeled
  `kagi.pw/inject: "true"` un-creatable cluster-wide.
- **Helm `genSelfSignedCert` + `lookup`** — worked under real Helm, but
  ArgoCD/Flux render with `helm template`, where `lookup` always returns empty.
  Every render minted a fresh keypair, so the release was permanently
  `OutOfSync` and each churn opened a window where the `caBundle` and the
  served certificate disagreed.

#### Upgrading from a chart release that still had `injection.certManager.*`

Both old paths converge on the same end state, but they get there differently
and the disruption window differs. In both cases the blast radius is limited to
pods labeled `kagi.pw/inject: "true"`; nothing else in the cluster is affected.

**From `certManager.enabled=true` (the old default).** cert-manager owned the
`Secret`, not Helm, so `helm upgrade` does **not** delete it. It survives with
`tls.crt`, `tls.key` and `ca.crt` but no `ca.key`, which the operator treats as
an invalid CA — so it mints a new one in place and republishes the `caBundle`.
The orphaned `Certificate` and `Issuer` *were* Helm-managed and are removed for
you; there is nothing to clean up by hand.

**From `certManager.enabled=false`.** Helm owned both the `Secret` and the
templated `caBundle`, so both go away at `helm upgrade` time — the window opens
immediately, before the new pod is even scheduled, and closes once the operator
has bootstrapped and published.

**Recommended either way:** delete the cert `Secret` just before upgrading, so
the operator bootstraps cleanly from nothing instead of reconciling half-owned
material:

```sh
kubectl delete secret kagi-operator-webhook-server-cert \
  -n kagi-operator-system --ignore-not-found
```

Use a maintenance window if anything in the cluster creates labeled pods
continuously. Expect the operator pod to restart once as it mints its first
keypair — that is by design, not a crash.

### Bringing your own certificate (`injection.existingCertSecret`)

**You almost certainly do not need this.** The default above requires nothing.
This exists for one case: organizations whose policy mandates that every
in-cluster certificate be issued by their own internal PKI. That is a compliance
requirement rather than a technical one, and without an escape hatch those
organizations could not adopt injection at all.

Create a `kubernetes.io/tls` Secret in the release namespace carrying all three
of `tls.crt`, `tls.key` and `ca.crt`:

```sh
kubectl create secret generic corp-pki-webhook-cert \
  -n kagi-operator-system \
  --type=kubernetes.io/tls \
  --from-file=tls.crt=webhook.crt \
  --from-file=tls.key=webhook.key \
  --from-file=ca.crt=corp-root-ca.crt
```

The certificate's SANs **must** cover
`kagi-operator-webhook.<namespace>.svc` — that is the name the API
server dials. The `.svc.cluster.local` form alone is not sufficient: a
certificate carrying only that will be refused at startup rather than run
broken-but-silent. (`existingCertSecret` has never shipped in a release, so no
existing installation is affected by this.) Then:

```sh
helm upgrade kagi-operator oci://ghcr.io/korurlabs/charts/kagi-operator \
  -n kagi-operator-system \
  --set injection.existingCertSecret=corp-pki-webhook-cert
```

> **Write access to this Secret is equivalent to admission control over every
> injected pod.** The operator publishes its `ca.crt` into the API server's
> trust store, so whoever can change that value decides which certificate the
> API server accepts for the webhook — and therefore what is injected into every
> labeled pod, including the projected Kagi token.
>
> The verification below is **not** a defence against that. Someone who can
> write the Secret can supply a fully self-consistent certificate, key and CA
> that verifies perfectly and publishes their own root; this is inherent to the
> pattern and is shared with Gatekeeper and Istio. What the checks do catch is
> *partial* tampering — appending to `ca.crt`, swapping one field — and honest
> misconfiguration. **RBAC on this Secret is the actual control.** Treat it like
> a signing key and do not hand a CI job blanket write access to it just because
> "you own the rotation".

What changes:

- The operator generates nothing, rotates nothing, and **never writes to that
  Secret**. It is yours.
- It **verifies** the material — not just that the three keys are present:
  `tls.crt` and `tls.key` must be a real keypair, `tls.crt` must chain to
  `ca.crt` as a server certificate, and it must currently be valid for the
  webhook Service's DNS name. Anything else is refused with a message naming the
  specific mismatch. The same check runs on **every** sync, so swapping *part* of
  the Secret's contents later — appending an anchor, replacing one field — is
  caught too. A coherent replacement of all four values is not; see the boundary
  note above.
- `ca.crt` must contain **nothing beyond the chain that signs `tls.crt`**, and
  must not contain a cross-signature — two *different* certificates sharing a
  subject and a public key, i.e. one re-issuing the other under a second signer.
  (An exact byte-for-byte duplicate is the same anchor listed twice; it grants no
  trust the bundle did not already grant, so it is harmless and accepted.
  Concatenated corporate bundles produce them routinely.) Everything in `ca.crt`
  becomes an API server trust anchor, so an extra
  certificate *appended* rather than substituted would silently widen what the
  API server accepts while the legitimate chain kept working. The same scan
  covers the trailing certificates in `tls.crt`, because chains are built through
  those as well. Leaf →
  intermediate → root bundles are fine, in either the "`tls.crt` carries the
  intermediates" or the "`ca.crt` carries intermediate and root" shape. An
  **unused** extra anchor — a cross-signed second root kept around for a
  migration, say — is rejected; that is deliberate, not an oversight. Open an
  issue if you have a real need for it.

  These two rules are **hygiene, not a boundary**. They catch a bundle that grew
  an anchor it does not need. They cannot tell a coherent bundle built around
  somebody else's root from a legitimate one — on this path the operator holds no
  private key, so it has nothing to compare a substituted CA against. RBAC on the
  Secret remains the control.
- It **refuses to start** on a Secret that fails any of the above, rather than
  serve behind a webhook whose `caBundle` it could never fill in.
- It still publishes the `caBundle` — from **your** `ca.crt` — because admission
  cannot work otherwise, and re-checks once a minute, so when your PKI rotates
  the **CA** underneath it admission keeps working with no action from you.
  Rotating the **leaf** under the same CA needs nothing at all: the kubelet
  reprojects the Secret and the operator reloads it.
- The Deployment mounts the Secret with `optional: false`, so the pod will not
  start until it exists. Create it first.

The pod spec carries `--webhook-cert-managed=false` on this path and nothing on
the default path, so `kubectl get deploy -o yaml` tells you which mode a cluster
is in — as does the operator's startup log line (`mode=user-supplied` vs
`mode=operator-managed`).

To return to zero-configuration TLS, unset the value; the operator resumes
issuing and rotating its own certificate into
`kagi-operator-webhook-server-cert`.

## CRDs

`crds.install` (default `true`) installs `kagisecrets.kagi.pw` and
`kagicertificates.kagi.pw`. Unlike a typical Helm chart, these CRDs are
**templated** (`templates/crds/*.yaml`, gated by this flag) rather than
placed in Helm's special `crds/` directory — that's the only way to make CRD
install itself toggleable via values. The trade-off, per
[Helm's own CRD guidance](https://helm.sh/docs/chart_best_practices/custom_resource_definitions/):

- **Upside:** `helm upgrade` *will* apply CRD schema changes shipped in a new
  chart version (a normal `crds/` directory never gets touched by `upgrade`).
- **Downside:** flipping `crds.install` to `false` on an upgrade, or running
  `helm uninstall`, will attempt to delete the CRDs — and therefore every
  `KagiSecret`/`KagiCertificate` object using them. `crds.keep` (default
  `true`) stamps `helm.sh/resource-policy: keep` specifically to protect
  against the `helm uninstall` case. Keep `crds.install` consistent across
  upgrades in any shared cluster.

### Upgrade note: `spec.organization` must be a UUID

Because this chart's CRDs are templated, a `helm upgrade` applies their schema
changes. `spec.organization` on `KagiSecret` and `KagiCertificate` is now
constrained to a canonical UUID (or the empty string, which keeps meaning "use
the organization the token is bound to"), and the operator refuses a malformed
value at reconcile time as well, with `Ready=False`, `reason=InvalidSpec`.

The value is sent verbatim as the `X-Organization-ID` cross-check, so a non-UUID
can never match a Kagi organization id. Before this change the mistake was
invisible at the point it was made: the Kagi API either answered `403` on every
request for the life of the object, or — with tenancy enforcement in `OFF` or
`SHADOW` — logged the mismatch server-side and served the request from the
token's own organization, so the cross-check the author asked for silently never
ran.

Check before upgrading; anything printed here will be rejected on its next
apply and will report `InvalidSpec` on its next reconcile:

```bash
kubectl get kagisecrets,kagicertificates -A \
  -o jsonpath='{range .items[?(@.spec.organization!="")]}{.kind}/{.metadata.namespace}/{.metadata.name} {.spec.organization}{"\n"}{end}' \
  | grep -vE ' [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
```

## Artifact Hub

`Chart.yaml` carries the standard `artifacthub.io/*` annotations (`operator:
"true"`, `operatorCapabilities: "Basic Install"`, `license`, `maintainers`,
`links`, `images`, `crds`, `crdsExamples`).

`../artifacthub-repo.yml` (one level up, at `charts/`)
is the repository-level ownership-claim file. It is **not** consumed by Helm,
it proves to Artifact Hub that Korur owns the
`ghcr.io/korurlabs/charts/kagi-operator` OCI repository. To register:

1. Add the repository in the [Artifact Hub control
   panel](https://artifacthub.io/control-panel/repositories) as an "OCI Helm
   chart" pointing at `oci://ghcr.io/korurlabs/charts/kagi-operator`.
2. Artifact Hub gives you a `repositoryID` — fill it into
   `artifacthub-repo.yml`'s `TODO`. **This is the only remaining manual step.**
3. The push itself is already wired: the public release workflow
   (`.github/workflows/kagi-operator-release.yml`, the "Publish Artifact Hub
   ownership metadata" step) `oras push`es `artifacthub-repo.yml` to that same
   `ghcr.io/korurlabs/charts/kagi-operator` path, tagged `artifacthub.io`, with
   media type
   `application/vnd.cncf.artifacthub.repository-metadata.layer.v1.yaml` (see
   [Artifact Hub's ownership-claim docs](https://artifacthub.io/docs/topics/repositories/#ownership-claim)).
   It runs on every `kagi-operator/v*` tag, so filling in the `repositoryID` and
   cutting a release is all that is left. Note this is the *public* release
   workflow, deliberately separate from the internal `kagi-operator-ci.yml`,
   which deploys the separate internal chart to Korur's own cluster.

## Verifying locally

```sh
helm lint charts/kagi-operator
helm template kagi-operator charts/kagi-operator
helm template kagi-operator charts/kagi-operator --set injection.enabled=false
helm template kagi-operator charts/kagi-operator --set auth.existingSecret=my-kagi-token
```
