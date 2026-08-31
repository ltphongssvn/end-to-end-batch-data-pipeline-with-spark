# policies/observability/observability.rego
# Minimum instrumentation, enforced as policy.
#
# WHY THIS EXISTS: extraction was instrumented, fetch was not, and nothing
# noticed. A 283MB network transfer with bounded retries ran blind until someone
# audited by hand. Telemetry added by good intentions decays; telemetry required
# by a gate does not.
#
# Observability-as-code in the literal sense: the same CI that governs the
# software governs what the software must make visible. OPA is already the
# decision point for extraction limits, so these rules live in the same engine
# rather than in a bespoke script nobody maintains.
#
# WHAT IS CHECKED, AND WHAT DELIBERATELY IS NOT.
# The input is an inventory built by walking the source with Python's ast module:
# which modules exist, which emit, whether they report terminal outcomes. Those
# are structural facts a parser can establish. Whether an event carries the RIGHT
# fields is semantic, and tests/test_telemetry.py answers it. Asking Rego to
# judge what it cannot see would produce a rule that passes while the telemetry
# is useless.
#
# THE EXEMPT LIST CARRIES A REASON PER ENTRY, because a list without governance
# is configuration drift with better branding. NIST defines an allowlist as a
# documented list allowed per policy decision -- owners, criteria, exceptions,
# change control. The unclassified rule below is that change control: a new
# module cannot be silently ignored, it must be classified deliberately.

# METADATA
# title: Minimum instrumentation
# description: |
#   Requires that every module performing observable work emits telemetry and
#   reports terminal outcomes, rather than leaving them to an exception.
# authors:
#   - ltphongssvn
package observability

import rego.v1

policy_version := "observability-policy/v1"

# Modules performing observable work: they do I/O, take locks, spend real time,
# or make decisions an operator may need explained. One that emits nothing is a
# blind spot by definition.
#
# Listed explicitly rather than inferred. "Does this matter operationally" is a
# judgement, and a heuristic would produce both false alarms and false silence --
# the two ways a gate loses credibility and gets switched off.
instrumented_modules := {
	"ingest/fetch.py",
	"ingest/extract.py",
}

# Legitimately silent, each with its reason.
exempt := {
	"telemetry.py": "defines the events; emitting its own would recurse",
	"valuetypes.py": "type definitions only, no runtime behaviour",
	"runcontext.py": "resolves identity at import, before telemetry exists",
	"contracts.py": "build-time schema generation, not a pipeline path",
	"atomicio.py": "primitives whose instrumented callers report the outcome",
	"session.py": "thin Spark session builder, no branching behaviour",
	"config.py": "CLI whose stdout contract IS its interface",
	"ingest/policy.py": "decisions are emitted by the caller that acts on them",
	"ingest/probe.py": "CLI with a documented stdout contract",
}

# --- Input completeness ------------------------------------------------------
# A rule referencing a missing field evaluates to undefined, and an undefined
# deny contributes nothing. An inventory that failed to generate must fail the
# gate rather than silently pass it.

# TWO RULES, NOT ONE, AND THE SECOND IS THE ONE THAT MATTERS.
# An empty array is a DEFINED value in Rego, and only undefined is falsy -- so
# `not input.modules` never fires for {"modules": []}. No other rule matches an
# empty list either, leaving allow true: an inventory that generated nothing
# would have passed the gate. That is the exact fail-open shape this policy
# exists to prevent, occurring inside the policy itself. Presence is not the
# check; count is.
deny contains reason if {
	not input.modules
	reason := "inventory is missing; the generator did not run"
}

deny contains reason if {
	count(input.modules) == 0
	reason := "inventory is empty; the generator produced no modules"
}

deny contains reason if {
	some index, module in input.modules
	not "path" in object.keys(module)
	reason := sprintf("inventory entry %v has no path", [index])
}

deny contains reason if {
	some module in input.modules
	not "emits" in object.keys(module)
	reason := sprintf("inventory entry %v has no emits count", [module.path])
}

# --- Minimum instrumentation -------------------------------------------------

deny contains reason if {
	some module in input.modules
	module.path in instrumented_modules
	module.emits == 0
	reason := sprintf("%v performs observable work but emits nothing", [module.path])
}

# Without a terminal outcome a query can count starts and never learn how many
# finished, which is the shape of an incident nobody can close.
deny contains reason if {
	some module in input.modules
	module.path in instrumented_modules
	module.emits > 0
	not module.has_success_event
	reason := sprintf("%v never emits a success outcome", [module.path])
}

deny contains reason if {
	some module in input.modules
	module.path in instrumented_modules
	module.emits > 0
	not module.has_failure_event
	reason := sprintf("%v never emits a failure outcome", [module.path])
}

# UNCLASSIFIED is the state every new file starts in, and failing here is the
# point: it forces a deliberate decision instead of letting a silent module slip
# in unnoticed.
deny contains reason if {
	some module in input.modules
	not module.path in instrumented_modules
	not module.path in object.keys(exempt)
	reason := sprintf(
		"%v is neither instrumented nor exempt; classify it in the policy",
		[module.path],
	)
}

# --- Decision ----------------------------------------------------------------

default allow := false

allow if count(deny) == 0

# METADATA
# entrypoint: true
# description: |
#   Whether the codebase meets minimum instrumentation requirements, with a
#   reason for every shortfall.
decision := {
	"allow": allow,
	"policy_version": policy_version,
	"reasons": deny,
}
