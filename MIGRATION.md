# Migration from korurlabs/village

The operator is moving from the private monorepo `korurlabs/village`
(`projects/kagi/operator`) to this repository. The move is done in steps, so
nothing that runs today breaks before its replacement here is proven.

## Status: copy (step 1)

`korurlabs/village` is still the source of truth. Make operator changes there;
pull requests here are for the migration only. This repository is a copy,
refreshed with:

```sh
hack/sync-from-village.py <path to a village checkout>
```

The script replaces everything that came from village, keeps what belongs to
this repository (`.github/`, `contract/`, this file and the script), and
rewrites the monorepo paths so the copy builds on its own: the image builds
from the repository root, and the operator's API contract bundle sits in
`contract/clients/operator.json`. `hack/village-commit` names the village
commit the copy was taken from. The first copy was taken with a fresh history,
so nothing from village's history is published.

What runs here today:

| Workflow | Does | Publishes |
|---|---|---|
| `ci.yml` | `make test`, generated-files check, chart lint and render, image build | nothing |
| `test-e2e.yml` | e2e suite in a kind cluster, manual | nothing |
| `release.yml` | image, Helm chart and GitHub release on a `v*` tag | nothing until `PUBLISH_RELEASES=true` |

## Step 2: public releases from here

1. Sync, and check that CI is green.
2. Remove `.github/workflows/kagi-operator-release.yml` from village, so only
   one workflow publishes to `ghcr.io/korurlabs/kagi-operator` and
   `ghcr.io/korurlabs/charts/kagi-operator`.
3. Connect both ghcr.io packages to this repository (package settings,
   "Manage Actions access": write for `korurlabs/kagi-operator`), so this
   repository's `GITHUB_TOKEN` can push to them.
4. Set the repository variable `PUBLISH_RELEASES=true` and tag the next
   version, `v0.4.2` or later (village used `kagi-operator/v0.4.1`).
5. Register the chart on Artifact Hub and fill in `repositoryID` in
   `charts/artifacthub-repo.yml` (see that file).

## Step 3: internal deploy from here

The internal pipeline (`kagi-operator-ci.yml` in village) builds into
`senseyprodacr.azurecr.io` on every push to `main` and sets the image tag in
village's `gitops/platform/stormcloud/kagi-operator/values.yaml`. Moving it
needs:

1. In `korurlabs/kara`, Entra root: a federated credential on the app
   registration `github-actions-senseylabs` for
   `repo:korurlabs@157635970/kagi-operator@1466722855:ref:refs/heads/main`.
2. Repository secrets `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and
   `AZURE_SUBSCRIPTION_ID` here, the same values village uses.
3. An environment `gitops` here, limited to `main`, holding the
   `korur-prod-gitops-write` App's client ID and private key. The deploy job
   mints a token for `korurlabs/village` and commits the tag there, as today.
4. A `deploy` workflow here, ported from village's `kagi-operator-ci.yml`.
   Then remove that workflow from village. The image tag sequence restarts, so
   start it above village's last `0.0.<run_number>`.

## Step 4: source of truth moves here

1. Last sync, then remove `projects/kagi/operator` from village and point its
   docs here.
2. Remove the sync script, `hack/village-commit` and the "copy" status above.
3. Keep `contract/clients/operator.json` in step with the Kagi API contract in
   village: a contract change that touches the operator bundle needs a pull
   request here too, `make api-generate` included.
