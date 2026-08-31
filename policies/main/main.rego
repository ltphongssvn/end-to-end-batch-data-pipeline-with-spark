# policies/main/main.rego
# The composite entrypoint: one query, every source-derived decision.
#
# WHY THIS EXISTS RATHER THAN A LOOP IN PYTHON. The obvious shape is a script
# that runs `opa eval` once per policy and collects results, and that
# reimplements in Python what OPA composes natively. The documented pattern is
# an entrypoint policy that composes the others and UNIONS their deny reasons
# into one final set -- so composition lives in the policy language, is tested
# by opa test, and counts toward policy coverage like every other rule.
#
# It also fixes failure attribution. Separate evaluations produce separate
# failures, so an agent seeing "observability failed" and "architecture failed"
# has to work out that both came from the same unclassified new file. One
# decision reports one verdict with every reason, each tagged by its source.
#
# ADDING A POLICY MEANS ADDING IT HERE. A policy under policies/ that is linted
# and tested but never composed would decide nothing while looking healthy --
# the quietest way for a control to stop working.

# METADATA
# title: Composite source policy
# description: |
#   Unions every policy that decides about the source tree into a single
#   allow/deny with attributed reasons.
# authors:
#   - ltphongssvn
package main

import rego.v1

import data.architecture
import data.observability

# Each composed policy, keyed by the name that tags its reasons.
composed := {
	"observability": observability.decision,
	"architecture": architecture.decision,
}

# Every reason from every policy, tagged with its origin, so a failure says
# which control refused and why in one place.
deny contains reason if {
	some name, verdict in composed
	some detail in verdict.reasons
	reason := sprintf("%s: %s", [name, detail])
}

# Versions of everything that contributed, so an audit reading a CI log knows
# which revision of which rules produced the verdict.
policy_versions[name] := version if {
	some name, verdict in composed
	version := verdict.policy_version
}

default allow := false

allow if count(deny) == 0

# METADATA
# entrypoint: true
# description: |
#   The single decision a CI gate queries: allow, every attributed reason, and
#   the version of each policy that contributed.
decision := {
	"allow": allow,
	"reasons": deny,
	"policy_versions": policy_versions,
}
