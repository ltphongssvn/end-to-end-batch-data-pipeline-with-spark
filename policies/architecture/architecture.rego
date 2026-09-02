# policies/architecture/architecture.rego
# The acquisition boundary, enforced.
#
# THE INVARIANT: acquisition and extraction happen ONCE, on the driver, before
# Spark sees anything. Spark then reads a committed artifact whose identity is
# already established.
#
#   external source
#         |
#         v   deterministic acquisition   <- driver only, this layer
#   immutable raw artifact   (sha256 + recorded policy decision)
#         |
#         v   DataFrame read
#   schema validation and transformation
#
# WHY THIS IS STRONGER THAN "RETRIES ARE AMBIGUOUS": Spark uses SPECULATIVE
# EXECUTION. A task judged slow is duplicated on another node and whichever
# finishes first wins, so a side effect inside a transformation runs an
# unpredictable number of times BY DESIGN, not merely on failure. A 283MB
# download inside a transformation could run twice, concurrently, with neither
# copy being an error. The locks and atomic publishes in atomicio would make
# that SAFE without making it CORRECT: the work would still be repeated, and
# the extraction policy decision would be taken once per attempt rather than
# once per artifact.
#
# The ingest layer is Spark-free today. This policy keeps it that way when the
# next agent adds a module and reaches for a DataFrame.
#
# EVALUATED ON THE TRANSITIVE CLOSURE, not direct imports. "ingest/extract.py
# does not import pyspark" is true and insufficient: importing session.py,
# which imports pyspark, is the same dependency and invisible to a flat scan.
# Import Linter follows indirect chains for exactly this reason; the inventory
# computes the closure so enforcement stays in one engine instead of adding a
# second tool overlapping OPA.

# METADATA
# title: Layer boundaries
# description: |
#   Keeps acquisition deterministic and driver-side by forbidding Spark
#   anywhere in the ingest layer, following indirect imports.
# authors:
#   - ltphongssvn
package architecture

import rego.v1

policy_version := "architecture-policy/v1"

# The deterministic acquisition boundary. Everything here runs on the driver,
# exactly once per artifact, and commits before Spark starts.
ingest_layer := {
	"ingest/fetch.py",
	"ingest/extract.py",
	"ingest/policy.py",
	"ingest/probe.py",
	"atomicio.py",
}

# Packages the ingest layer must never reach, each with the reason it is
# forbidden -- a denial an operator cannot explain is one they will bypass.
forbidden_in_ingest := {
	"pyspark": "acquisition must not run inside a Spark transformation",
	"delta": "the raw layer writes plain files; Delta belongs to curated onward",
}

# The only module permitted to build a Spark session. Listed rather than
# inferred, so adding a second one is a deliberate and reviewable act.
spark_owners := {"session.py"}

# THE ORCHESTRATOR MUST NOT ENTER THIS ENVIRONMENT.
#
# Resolving `dagster` alongside this stack downgrades protobuf from 7.36.0 to
# 6.33.6 -- a MAJOR version, underneath a Spark Connect client whose whole
# premise is matching the Databricks server. That is the drift class this
# project pins everything to prevent, and it would appear as UDFs failing at
# runtime rather than as a resolution error.
#
# Dagster's own architecture is the fix: the orchestrator runs in a separate
# code location, and this environment carries only `dagster-pipes`, which
# resolves to exactly one package with no dependencies. Verified: protobuf
# stays at 7.36.0.
#
# `uv add dagster` here is therefore a layer violation, not a preference.
forbidden_everywhere := {
	"dagster": "the orchestrator belongs in its own code location",
	"dagster-webserver": "orchestration UI, same isolation boundary",
	"dagster-graphql": "orchestration API, same isolation boundary",
}

# --- Input completeness ------------------------------------------------------
# A rule referencing a missing field is undefined and contributes no denial, so
# an inventory that failed to generate must fail rather than pass silently.

deny contains reason if {
	not input.modules
	reason := "inventory is missing; the generator did not run"
}

deny contains reason if {
	count(input.modules) == 0
	reason := "inventory is empty; the generator produced no modules"
}

deny contains reason if {
	some module in input.modules
	not "effective_imports" in object.keys(module)
	reason := sprintf("inventory entry %v has no effective_imports", [module.path])
}

# --- The boundary ------------------------------------------------------------

deny contains reason if {
	some module in input.modules
	module.path in ingest_layer
	some dependency, why in forbidden_in_ingest
	dependency in module.effective_imports
	reason := sprintf("%v reaches %v -- %v", [module.path, dependency, why])
}

# PRESENCE IN THE LOCKFILE, NOT VERSION -- and that distinction was measured,
# not assumed.
#
# An import rule catches `import dagster` and misses `uv add dagster`, because
# the damage is done by the INSTALL. A protobuf version check is also not
# enough: running `uv add dagster` with the resolver constraint in place did
# NOT fail. uv held protobuf at 7.x and satisfied it by installing dagster
# 1.3.10 -- a 2023 release -- instead of 1.13.19.
#
# uv documents this: "instead of failing, the resolver will pick an older
# version without the bound, circumventing the bound", and warns it "can end up
# picking a version that's old enough that it doesn't depend on the conflicting
# package, but also doesn't work with your code". Two 2026 incidents show the
# same class shipping: limacharlie stranded users on 5.3.0 where a stale
# install self-reports as current, and DANDI resolved a client so old it
# crashed on first call.
#
# A silent three-year backslide looks like success. Presence is the check.
deny contains reason if {
	some dependency, why in forbidden_everywhere
	input.locked_packages[dependency]
	reason := sprintf(
		"uv.lock contains %v (%v) -- %v",
		[dependency, input.locked_packages[dependency], why],
	)
}

# The version this boundary exists to protect, asserted directly so a downgrade
# arriving through ANY path is caught rather than only the one predicted.
deny contains reason if {
	version := input.locked_packages.protobuf
	not startswith(version, "7.")
	reason := sprintf(
		"protobuf is %v; Spark Connect 4.0 runs against the 7.x line and a downgrade breaks UDFs on Databricks",
		[version],
	)
}

# Spark outside its declared owner is boundary erosion even when the module is
# not in the ingest layer, because it means a second place builds sessions.
deny contains reason if {
	some module in input.modules
	not module.path in spark_owners
	"pyspark" in module.effective_imports
	reason := sprintf("%v reaches pyspark but is not a declared Spark owner", [module.path])
}

# --- Decision ----------------------------------------------------------------

default allow := false

allow if count(deny) == 0

# METADATA
# entrypoint: true
# description: |
#   Whether the codebase respects its layer boundaries, with a reason for every
#   violation.
decision := {
	"allow": allow,
	"policy_version": policy_version,
	"reasons": deny,
}
