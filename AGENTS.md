# operator - AI Agent Guide

## Project Structure

**Single-group layout (default):**
```
cmd/main.go                    Manager entry (registers controllers/webhooks)
api/<version>/*_types.go       CRD schemas (+kubebuilder markers)
api/<version>/zz_generated.*   Auto-generated (DO NOT EDIT)
internal/controller/*          Reconciliation logic
internal/webhook/*             Validation/defaulting (if present)
config/crd/bases/*             Generated CRDs (DO NOT EDIT)
config/rbac/role.yaml          Generated RBAC (DO NOT EDIT)
config/samples/*               Example CRs (edit these)
Makefile                       Build/test/deploy commands
PROJECT                        Kubebuilder metadata Auto-generated (DO NOT EDIT)
```

**Multi-group layout** (for projects with multiple API groups):
```
api/<group>/<version>/*_types.go       CRD schemas by group
internal/controller/<group>/*          Controllers by group
internal/webhook/<group>/<version>/*   Webhooks by group and version (if present)
```

Multi-group layout organizes APIs by group name (e.g., `batch`, `apps`). Check the `PROJECT` file for `multigroup: true`.

**To convert to multi-group layout:**
1. Run: `kubebuilder edit --multigroup=true`
2. Move APIs: `mkdir -p api/<group> && mv api/<version> api/<group>/`
3. Move controllers: `mkdir -p internal/controller/<group> && mv internal/controller/*.go internal/controller/<group>/`
4. Move webhooks (if present): `mkdir -p internal/webhook/<group> && mv internal/webhook/<version> internal/webhook/<group>/`
5. Update import paths in all files
6. Fix `path` in `PROJECT` file for each resource
7. Update test suite CRD paths (add one more `..` to relative paths)

## Critical Rules

### Never Edit These (Auto-Generated)
- `config/crd/bases/*.yaml` - from `make manifests`
- `config/rbac/role.yaml` - from `make manifests`
- `config/webhook/manifests.yaml` - from `make manifests`
- `**/zz_generated.*.go` - from `make generate`
- `PROJECT` - from `kubebuilder [OPTIONS]`

### Never Remove Scaffold Markers
Do NOT delete `// +kubebuilder:scaffold:*` comments. CLI injects code at these markers.

### Keep Project Structure
Do not move files around. The CLI expects files in specific locations.

### Always Use CLI Commands
Always use `kubebuilder create api` and `kubebuilder create webhook` to scaffold. Do NOT create files manually.

### E2E Tests Require an Isolated Kind Cluster
The e2e tests are designed to validate the solution in an isolated environment (similar to GitHub Actions CI).
Ensure you run them against a dedicated [Kind](https://kind.sigs.k8s.io/) cluster (not your “real” dev/prod cluster).

## After Making Changes

**After editing `*_types.go` or markers:**
```
make manifests  # Regenerate CRDs/RBAC from markers
make generate   # Regenerate DeepCopy methods
```

**After editing `*.go` files:**
```
make lint-fix   # Auto-fix code style
make test       # Run unit tests
```

## CLI Commands Cheat Sheet

### Create API (your own types)
```bash
kubebuilder create api --group <group> --version <version> --kind <Kind>
```

### Deploy Image Plugin (scaffold to deploy/manage ANY container image)

Generate a controller that deploys and manages a container image (nginx, redis, memcached, your app, etc.):

```bash
# Example: deploying memcached
kubebuilder create api --group example.com --version v1alpha1 --kind Memcached \
  --image=memcached:alpine \
  --plugins=deploy-image.go.kubebuilder.io/v1-alpha
```

Scaffolds good-practice code: reconciliation logic, status conditions, finalizers, RBAC. Use as a reference implementation.


### Create Webhooks
```bash
# Validation + defaulting
kubebuilder create webhook --group <group> --version <version> --kind <Kind> \
  --defaulting --programmatic-validation

# Conversion webhook (for multi-version APIs)
kubebuilder create webhook --group <group> --version v1 --kind <Kind> \
  --conversion --spoke v2
```

### Controller for Core Kubernetes Types
```bash
# Watch Pods
kubebuilder create api --group core --version v1 --kind Pod \
  --controller=true --resource=false

# Watch Deployments
kubebuilder create api --group apps --version v1 --kind Deployment \
  --controller=true --resource=false
```

### Controller for External Types (e.g., from other operators)

Watch resources from external APIs (cert-manager, Argo CD, Istio, etc.):

```bash
# Example: watching cert-manager Certificate resources
kubebuilder create api \
  --group cert-manager --version v1 --kind Certificate \
  --controller=true --resource=false \
  --external-api-path=github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1 \
  --external-api-domain=io \
  --external-api-module=github.com/cert-manager/cert-manager
```

**Note:** Use `--external-api-module=<module>@<version>` only if you need a specific version. Otherwise, omit `@<version>` to use what's in go.mod.

### Webhook for External Types

```bash
# Example: validating external resources
kubebuilder create webhook \
  --group cert-manager --version v1 --kind Issuer \
  --defaulting \
  --external-api-path=github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1 \
  --external-api-domain=io \
  --external-api-module=github.com/cert-manager/cert-manager
```

## Testing & Development

```bash
make test              # Run unit tests (uses envtest: real K8s API + etcd)
make run               # Run locally (uses current kubeconfig context)
```

Tests use **Ginkgo + Gomega** (BDD style). Check `suite_test.go` for setup.

## Deployment Workflow

```bash
# 1. Regenerate manifests
make manifests generate

# 2. Build & deploy
export IMG=<registry>/<project>:tag
make docker-build docker-push IMG=$IMG  # Or: kind load docker-image $IMG --name <cluster>
make deploy IMG=$IMG

# 3. Test
kubectl apply -k config/samples/

# 4. Debug
kubectl logs -n <project>-system deployment/<project>-controller-manager -c manager -f
```

### API Design

**Key markers for** `api/<version>/*_types.go`:

```go
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].status"

// On fields:
// +kubebuilder:validation:Required
// +kubebuilder:validation:Minimum=1
// +kubebuilder:validation:MaxLength=100
// +kubebuilder:validation:Pattern="^[a-z]+$"
// +kubebuilder:default="value"
```

- **Use** `metav1.Condition` for status (not custom string fields)
- **Use predefined types**: `metav1.Time` instead of `string` for dates
- **Follow K8s API conventions**: Standard field names (`spec`, `status`, `metadata`)

### Controller Design

**RBAC markers in** `internal/controller/*_controller.go`:

```go
// +kubebuilder:rbac:groups=mygroup.example.com,resources=mykinds,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=mygroup.example.com,resources=mykinds/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=mygroup.example.com,resources=mykinds/finalizers,verbs=update
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
```

**Implementation rules:**
- **Idempotent reconciliation**: Safe to run multiple times
- **Re-fetch before updates**: `r.Get(ctx, req.NamespacedName, obj)` before `r.Update` to avoid conflicts
- **Structured logging**: `log := log.FromContext(ctx); log.Info("msg", "key", val)`
- **Owner references**: Enable automatic garbage collection (`SetControllerReference`)
- **Watch secondary resources**: Use `.Owns()` or `.Watches()`, not just `RequeueAfter`
- **Finalizers**: Clean up external resources (buckets, VMs, DNS entries)

### Logging

**Follow Kubernetes logging message style guidelines:**

- Start from a capital letter
- Do not end the message with a period
- Active voice: subject present (`"Deployment could not create Pod"`) or omitted (`"Could not create Pod"`)
- Past tense: `"Could not delete Pod"` not `"Cannot delete Pod"`
- Specify object type: `"Deleted Pod"` not `"Deleted"`
- Balanced key-value pairs

```go
log.Info("Starting reconciliation")
log.Info("Created Deployment", "name", deploy.Name)
log.Error(err, "Failed to create Pod", "name", name)
```

**Reference:** https://github.com/kubernetes/community/blob/master/contributors/devel/sig-instrumentation/logging.md#message-style-guidelines

### Webhooks
- **Create all types together**: `--defaulting --programmatic-validation --conversion`
- **When`--force`is used**: Backup custom logic first, then restore after scaffolding
- **For multi-version APIs**: Use hub-and-spoke pattern (`--conversion --spoke v2`)
  - Hub version: Usually oldest stable version (v1)
  - Spoke versions: Newer versions that convert to/from hub (v2, v3)
  - Example: `--group crew --version v1 --kind Captain --conversion --spoke v2` (v1 is hub, v2 is spoke)

### Learning from Examples

The **deploy-image plugin** scaffolds a complete controller following good practices. Use it as a reference implementation:

```bash
kubebuilder create api --group example --version v1alpha1 --kind MyApp \
  --image=<your-image> --plugins=deploy-image.go.kubebuilder.io/v1-alpha
```

Generated code includes: status conditions (`metav1.Condition`), finalizers, owner references, events, idempotent reconciliation.

## This Repository — What Diverges From The Scaffold

The rest of this document is the generic kubebuilder guide. These things are
specific to `kagi-operator` and are easy to destroy with a regeneration command:

- **`internal/certs/`** — the webhook serving certificate is **self-bootstrapped**
  by the operator (generate, publish, rotate, verify, tamper-monitor). This is
  deliberate: there is **no cert-manager dependency**, and none should be added.
  `config/certmanager/` style wiring is intentionally absent.
- **Four load-bearing kustomize patches** that must survive every
  `make manifests` / `make build-installer` run — check `git diff` under
  `config/` afterwards and confirm they are still applied:
  - `config/rbac/webhook_scope_patch.yaml` — narrows the operator's webhook-config
    RBAC to its own resource names.
  - `config/rbac/webhookname_ref.yaml` — registers `rules/resourceNames` as a
    kustomize `nameReference`, so the scoped RBAC above is rewritten by
    `namePrefix` in lockstep with the `MutatingWebhookConfiguration` it names.
    Without it the two drift apart the moment the prefix changes and the operator
    loses the ability to publish its own `caBundle`.
  - `config/webhook/objectselector_patch.yaml` — the `objectSelector` that makes
    injection opt-in via the `kagi.pw/inject` **label** (labels only; annotations
    cannot gate admission).
  - `config/default/manager_webhook_args_patch.yaml` — appends
    `--webhook-cert-path` with a JSON 6902 `add` on `/args/-`. **Never move a flag
    into `manager_webhook_patch.yaml`**: a strategic-merge patch REPLACES a
    `[]string` field (`Container.Args` carries no `patchMergeKey`), so an `args:`
    block there silently deletes `--leader-elect`, `--health-probe-bind-address`,
    `--metrics-bind-address` and the default-token flags from the released
    `dist/install.yaml`. New flags go in `config/manager/manager.yaml` or in
    another 6902 append.
- **`config/default/kustomization.yaml` pins `namespace: kagi-operator-system` and
  `namePrefix: kagi-operator-`** so the raw bundle lands where the Helm chart and
  all three doc locales say it does. Do not revert to the kubebuilder scaffold's
  `operator-system` / `operator-`. If either changes, re-render and confirm: the
  rendered `ClusterRole` `resourceNames` is still **string-equal** to the rendered
  `MutatingWebhookConfiguration` name, the `replacements:` block still fills
  `KAGI_WEBHOOK_SERVICE_NAME` / `KAGI_MUTATING_WEBHOOK_NAME`, and no rendered name
  exceeds 63 characters.
- **`dist/install.yaml`** — regenerated by the release CI
  (`.github/workflows/kagi-operator-release.yml` runs `make build-installer` with
  the released image tag). Do not hand-edit it and do not treat a local
  regeneration as the source of truth. Note `make build-installer` mutates
  `config/manager/kustomization.yaml` (image tag) as a side effect — restore that
  file after running it locally.
- **`charts/kagi-operator/`** — hand-written, see the warning under Option 2 below.

## Authentication to the Kagi API (`--kagi-auth`)

The manager flag `--kagi-auth` (env `KAGI_AUTH`, chart `auth.mode`) decides how
the operator authenticates when an object names no `spec.tokenSecret`. Any value
other than the two below fails start-up (`cmd/kagi_auth.go`).

- `token-secret` (default): the PAT in `--default-token-secret`, as before. Every
  existing install keeps it.
- `exchange`: `kagiclient.WorkloadTokenSource` reads the projected ServiceAccount
  token at `/var/run/secrets/kagi/token` (`kagiclient.DefaultServiceAccountTokenPath`)
  and posts the RFC 8693 form (`grant_type`, `subject_token`,
  `subject_token_type=urn:ietf:params:oauth:token-type:jwt`, one `resource`
  `https://<api-host>/kagi/apps/<appId>/environments/<environmentSlug>`) to
  `POST /kagi/auth/token`. It caches one token per (app, environment) pair and
  re-exchanges 60 s before `expires_in` (half the lifetime for a shorter token).
  `FetchSecrets` and `GetSecretsVersion` pass their pair through
  `kagiclient.TokenScope`; every other call names no pair and is refused with
  `kagiclient.ErrTokenScopeRequired` before any request.

The operator never names a workload role. The admin writes one in the portal
(Integrations, the cluster's connection) whose Kubernetes rule trusts the
operator's namespace and ServiceAccount and whose scopes list the pairs the
`KagiSecret`s read. `--kagi-api-url` must be the public API host, because the
exchange checks each `resource` host against it.

Under `exchange`:

- `spec.tokenSecret` on an object still wins for that object.
- A `KagiSecret` with `spec.folderPath` and no `spec.appId`, and every
  `KagiCertificate` without `spec.tokenSecret`, get `Ready=False` with reason
  `WorkloadTokenCannotResolve` and a message naming the fix. They are not
  retried: only a spec change can fix them.
- A refused exchange (401) gets `Ready=False` with reason `WorkloadAccessDenied`,
  naming the pair and the operator's connection under Integrations; the
  reconcile returns the error, so the failure rate limiter backs it off. Any
  other exchange failure (unreadable token file, network) is
  `TokenResolutionFailed`. In Injected mode an exchange failure on the version
  probe is reported the same way, never as `VersionProbeUnavailable`.

The projected volume `kagi-token` (audience `api.kagi.pw`, `expirationSeconds`
3600) is in `config/manager/manager.yaml` on every install, so switching the flag
needs no other manifest change; the chart renders it only when `auth.mode` is
`exchange`. Keep the chart's `auth.exchange.audience` equal to the API host.

`kagi-init` uses the same `WorkloadTokenSource` for the one pair of the pod's
`kagi.pw/app-id` and `kagi.pw/environment` annotations (`--app-id`,
`--environment`, `--sa-token-path`). The webhook, the annotations and the
projected volume it mounts are unchanged. A `kagi-init` image of an earlier
release keeps calling the deprecated `POST /kagi/auth/kubernetes/exchange`.

## Distribution Options

### Option 1: YAML Bundle (Kustomize)

```bash
# Generate dist/install.yaml from Kustomize manifests
make build-installer IMG=<registry>/<project>:tag
```

**Key points:**
- The `dist/install.yaml` is generated from Kustomize manifests (CRDs, RBAC, Deployment)
- Commit this file to your repository for easy distribution
- Users only need `kubectl` to install (no additional tools required)

**Example:** Users install with a single command:
```bash
kubectl apply -f https://raw.githubusercontent.com/<org>/<repo>/<tag>/dist/install.yaml
```

### Option 2: Helm Chart

> **DO NOT regenerate the chart.** `charts/kagi-operator/` is **hand-written** and
> is no longer a kubebuilder-scaffolded artifact. Running
> `kubebuilder edit --plugins=helm/v2-alpha` (with or without `--force`) will
> destroy the hand-written README, the annotated `values.yaml`, `NOTES.txt`, and
> the chart helpers such as `webhookCertSecretName`. There is no backup-and-restore
> path that survives it — edit the chart by hand instead.

**For development:**
```bash
helm lint charts/kagi-operator
helm template kagi-operator charts/kagi-operator --namespace kagi-system
helm upgrade --install kagi-operator charts/kagi-operator --namespace kagi-system --create-namespace
```

**For end users/production:**
```bash
helm install kagi-operator ./charts/kagi-operator --namespace kagi-system --create-namespace
```

When webhook or manifest changes land, update the chart templates by hand and
re-run `helm lint` / `helm template` (including with `injection.enabled=false`
and with `injection.existingCertSecret` set) to confirm all three configurations
still render.

### Publish Container Image

```bash
export IMG=<registry>/<project>:<version>
make docker-build docker-push IMG=$IMG
```

## References

### Essential Reading
- **Kubebuilder Book**: https://book.kubebuilder.io (comprehensive guide)
- **controller-runtime FAQ**: https://github.com/kubernetes-sigs/controller-runtime/blob/main/FAQ.md (common patterns and questions)
- **Good Practices**: https://book.kubebuilder.io/reference/good-practices.html (why reconciliation is idempotent, status conditions, etc.)
- **Logging Conventions**: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-instrumentation/logging.md#message-style-guidelines (message style, verbosity levels)

### API Design & Implementation
- **API Conventions**: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md
- **Operator Pattern**: https://kubernetes.io/docs/concepts/extend-kubernetes/operator/
- **Markers Reference**: https://book.kubebuilder.io/reference/markers.html

### Tools & Libraries
- **controller-runtime**: https://github.com/kubernetes-sigs/controller-runtime
- **controller-tools**: https://github.com/kubernetes-sigs/controller-tools
- **Kubebuilder Repo**: https://github.com/kubernetes-sigs/kubebuilder
