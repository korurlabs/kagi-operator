#!/usr/bin/env python3
"""Copy the operator from korurlabs/village into this repository.

Until the migration is done, korurlabs/village (projects/kagi/operator) is the
source of truth and this repository is a copy of it. Run this script to bring
the copy up to date, then commit the result in a pull request:

    hack/sync-from-village.py <path to a village checkout>

It replaces every tracked file that comes from village, keeps the files that
belong to this repository only (KEEP below), copies the operator's API
contract bundle into contract/, and rewrites the monorepo paths so the
repository builds on its own. Every rewrite asserts that it found the text it
replaces, so a change upstream fails here instead of shipping a broken copy.
The village commit it copied from is written to hack/village-commit.
"""

import pathlib
import shutil
import subprocess
import sys

# Paths owned by this repository, never overwritten or deleted by a sync.
KEEP = {
    ".git",
    ".github",
    # village builds from projects/kagi, where no ignore file applies; this
    # repository builds from its root with its own.
    ".dockerignore",
    ".gitignore",
    "contract",
    "hack/sync-from-village.py",
    "hack/village-commit",
    "MIGRATION.md",
}

# (file, old, new): each old text must occur exactly once.
REWRITES = [
    # The build context is the repository root instead of projects/kagi.
    ("Dockerfile", "COPY operator/go.mod operator/go.mod\nCOPY operator/go.sum operator/go.sum\nWORKDIR /workspace/operator\n",
     "COPY go.mod go.mod\nCOPY go.sum go.sum\n"),
    ("Dockerfile", "COPY operator/ .", "COPY . ."),
    ("Dockerfile", "COPY --from=builder /workspace/operator/manager .", "COPY --from=builder /workspace/manager ."),
    ("Dockerfile", "COPY --from=builder /workspace/operator/kagi-init /kagi-init", "COPY --from=builder /workspace/kagi-init /kagi-init"),
    ("Makefile", "# Context is projects/kagi, as in CI: the Dockerfile copies operator/. --load puts the",
     "# Context is the repository root, as in CI. --load puts the"),
    ("Makefile", "$(CONTAINER_TOOL) build --load -t ${IMG} -f Dockerfile ..", "$(CONTAINER_TOOL) build --load -t ${IMG} -f Dockerfile ."),
    # The contract bundle is copied to contract/ in this repository.
    ("Makefile", "# projects/kagi/contract/clients/operator.json, the bundle",
     "# contract/clients/operator.json (copied from korurlabs/village), the bundle"),
    ("Makefile", "CONTRACT_DIR := $(abspath $(CURDIR)/../contract)", "CONTRACT_DIR := $(CURDIR)/contract"),
    ("internal/kagiclient/models_contract_test.go",
     "// contractSpecPath is projects/kagi/contract/clients/operator.json, relative to this package.\n\tcontractSpecPath = \"../../../contract/clients/operator.json\"",
     "// contractSpecPath is contract/clients/operator.json, relative to this package.\n\tcontractSpecPath = \"../../contract/clients/operator.json\""),
    ("internal/kagiclient/oapi-codegen.yaml",
     "# projects/kagi/operator, never directly: the input is the operator bundle\n# projects/kagi/contract/clients/operator.json.",
     "# the repository root, never directly: the input is the operator bundle\n# contract/clients/operator.json."),
    # Links point at this repository.
    ("README.md", "https://github.com/korurlabs/village/releases/download/kagi-operator/v<VERSION>/install.yaml",
     "https://github.com/korurlabs/kagi-operator/releases/download/v<VERSION>/install.yaml"),
    ("charts/kagi-operator/Chart.yaml",
     "# The operator lives inside the korurlabs/village monorepo (there is no\n"
     "# standalone korurlabs/kagi-operator repository); the public release workflow\n"
     "# that publishes this chart runs there too. Artifact Hub renders this as the\n"
     "# listing's prominent \"source\" link, so it must point at the real tree.\n"
     "sources:\n  - https://github.com/korurlabs/village/tree/main/projects/kagi/operator",
     "# Artifact Hub renders this as the listing's prominent \"source\" link.\n"
     "sources:\n  - https://github.com/korurlabs/kagi-operator"),
    ("charts/kagi-operator/Chart.yaml",
     "      url: https://github.com/korurlabs/village/tree/main/projects/kagi/operator",
     "      url: https://github.com/korurlabs/kagi-operator"),
    ("charts/kagi-operator/Chart.yaml", "# Matches projects/kagi/operator/LICENSE (Apache-2.0)", "# Matches LICENSE (Apache-2.0)"),
    ("charts/kagi-operator/Chart.yaml", "# projects/kagi/operator/Dockerfile. kagi-init", "# Dockerfile. kagi-init"),
    ("charts/kagi-operator/README.md", "(one level up, at `projects/kagi/operator/charts/`)", "(one level up, at `charts/`)"),
]


def kept(rel: pathlib.PurePosixPath) -> bool:
    s = rel.as_posix()
    return any(s == k or s.startswith(k + "/") for k in KEEP)


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    village = pathlib.Path(sys.argv[1]).resolve()
    src = village / "projects/kagi/operator"
    bundle = village / "projects/kagi/contract/clients/operator.json"
    versions = village / "projects/kagi/contract/tools.versions"
    for p in (src, bundle, versions):
        if not p.exists():
            sys.exit(f"not found: {p}")
    repo = pathlib.Path(__file__).resolve().parent.parent

    # Remove the tracked files that came from village, so files deleted there
    # go here too. Untracked files (bin/, cover.out, ...) are left alone.
    ours = subprocess.run(["git", "-C", str(repo), "ls-files", "-z"],
                          check=True, capture_output=True, text=True).stdout.split("\0")
    for name in filter(None, ours):
        rel = pathlib.PurePosixPath(name)
        if kept(rel):
            continue
        p = repo / rel
        p.unlink(missing_ok=True)
        for d in p.parents:
            if d == repo or any(d.iterdir()):
                break
            d.rmdir()

    # Copy the operator, except its own .github (village never runs it; this
    # repository has its own workflows).
    tracked = subprocess.run(["git", "-C", str(src), "ls-files", "-z", "."],
                             check=True, capture_output=True, text=True).stdout.split("\0")
    for name in filter(None, tracked):
        rel = pathlib.PurePosixPath(name)
        if kept(rel):
            continue
        dst = repo / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src / rel, dst)

    (repo / "contract/clients").mkdir(parents=True, exist_ok=True)
    shutil.copy2(bundle, repo / "contract/clients/operator.json")
    shutil.copy2(versions, repo / "contract/tools.versions")

    for name, old, new in REWRITES:
        f = repo / name
        text = f.read_text()
        n = text.count(old)
        if n != 1:
            sys.exit(f"{name}: expected 1 occurrence of {old!r}, found {n}; update REWRITES")
        f.write_text(text.replace(old, new))

    commit = subprocess.run(["git", "-C", str(village), "rev-parse", "HEAD"],
                            check=True, capture_output=True, text=True).stdout.strip()
    (repo / "hack/village-commit").write_text(commit + "\n")
    print(f"synced from korurlabs/village {commit}")


if __name__ == "__main__":
    main()
