<!-- README.md -->
# End-to-End Batch Data Pipeline with Apache Spark

A three-layer lakehouse (raw → curated → serving) built on PySpark and Delta
Lake, targeting Databricks Free Edition serverless compute.

## Quick start

```bash
git clone git@github.com:ltphongssvn/end-to-end-batch-data-pipeline-with-spark.git
cd end-to-end-batch-data-pipeline-with-spark
mise run setup     # installs runtimes, dependencies, and git hooks
mise run check     # the full quality gate
```

`mise run setup` is the only command needed on a fresh clone. It is idempotent
and refuses to run if `core.hooksPath` is set, rather than silently overwriting
another tool's hooks.

## Runtime target

Pinned to Databricks Free Edition → serverless → **environment version 5**:

| Component | Version | Why pinned |
|---|---|---|
| Python | 3.12.3 | Spark Connect requires the client and server to share a Python **minor** version, or every Python UDF fails at runtime |
| JDK | Temurin 17 | Spark 4.x default build target; matches the serverless runtime |
| Spark | 4.0.x | `delta-spark` moves in lockstep with Spark |
| Scala | 2.13 | A 2.12 Delta JAR would fail on deploy |

Local and remote versions match by construction, not by convention.

## Layout

```
conf/pipeline.yml     pipeline + cluster config, validated at commit time
src/spark_batch_pipeline/
  config.py           Pydantic models: the governance layer
  session.py          the one SparkSession builder, shared by tests and jobs
tests/                pytest + chispa
mise.toml             runtimes and tasks -- the single source of truth
lefthook.yml          git hooks; every command is `mise run <task>`
```

## How the quality gate works

One task, `check`, defines the gate. A laptop, a git hook, and CI all run the
same thing, so a green commit means a green pipeline.

**On commit** (fast, scoped to the change): format → lint → secret scan of the
index → config validation → type check. Then the commit message is checked
against Conventional Commits.

**On push**: full-history secret scan and the test suite.

**In CI**: `mise run check`, which is strictly *broader* than the hooks. It
re-scans the entire history, because `git commit --no-verify` bypasses every
local hook and the pre-commit scan only ever sees the incoming change. The
branch ruleset makes passing it a condition of merging.

### What the config layer rejects

Failures land at commit time, not on a running cluster:

- Spark versions outside the supported envelope
- Missing or out-of-range `autotermination_minutes` (a cluster nobody shuts down bills until someone notices)
- Worker counts above the ceiling
- Unknown fields — a typo becomes a loud failure instead of a silent no-op
- Overlapping raw/curated/serving paths, which let a curated write clobber source data
- Duplicate source names
- Credential-shaped literals and URLs with embedded credentials

Credentials are not modelled in YAML at all. `DatabricksSettings` reads them
from `DATABRICKS_*` environment variables as `SecretStr`, so there is no field
a token could be pasted into, and nothing leaks through a printed traceback.

## Workflow

```bash
git switch -c feature/my-change
mise run check      # optional; the hooks run it anyway
mise run pr         # push, open a PR, arm auto-merge
mise run pr-wait    # optional; block until it lands
mise run sync       # return to develop and prune merged branches
```

GitFlow with server-side enforcement: `develop` and `main` reject direct pushes
and force-pushes, only merge commits are permitted, and GitHub performs the
merge itself once the gate passes — no polling script, and it lands with the
laptop closed.

## Tooling notes

- **mise** owns the JDK and pins `uv`; **uv** owns the Python interpreter and the dependency lockfile. `mise.lock` and `uv.lock` are both committed.
- **betterleaks**, not gitleaks — same author, drop-in compatible, and BPE token-efficiency filtering rather than Shannon entropy. Precision matters as much as recall: a scanner that cries wolf trains people to bypass the hook.
- **Lefthook** hooks contain no tool versions or binary paths. Every command is `mise run <task>`, so hook config cannot drift from the toolchain.
