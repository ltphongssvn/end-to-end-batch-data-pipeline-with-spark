# policies/main/main_test.rego
# The composite is a policy like any other and gets the same treatment.
#
# What is tested here is not the individual rules -- those are covered in their
# own packages -- but the COMPOSITION: that a denial anywhere reaches the top,
# that every reason names the control that produced it, and that allow requires
# every policy to agree.

package main_test

import rego.v1

import data.main

# A codebase satisfying both policies: instrumented modules that emit, report
# terminal outcomes and report latency, and no ingest module reaching Spark.
compliant := {"modules": [
	{
		"path": "ingest/extract.py",
		"emits": 7,
		"has_success_event": true,
		"has_failure_event": true,
		"reports_duration": true,
		"effective_imports": ["hashlib", "zipfile"],
	},
	{
		"path": "ingest/fetch.py",
		"emits": 6,
		"has_success_event": true,
		"has_failure_event": true,
		"reports_duration": true,
		"effective_imports": ["httpx"],
	},
	{
		"path": "session.py",
		"emits": 0,
		"has_success_event": false,
		"has_failure_event": false,
		"reports_duration": false,
		"effective_imports": ["delta", "pyspark"],
	},
]}

# --- Composition -------------------------------------------------------------

test_compliant_codebase_is_allowed if {
	main.allow with input as compliant
}

test_no_reasons_when_every_policy_agrees if {
	count(main.deny) == 0 with input as compliant
}

test_decision_reports_every_policy_version if {
	# An audit reading a CI log must know WHICH revision of WHICH rules produced
	# the verdict, not merely that something passed.
	decision := main.decision with input as compliant
	decision.policy_versions.observability == "observability-policy/v1"
	decision.policy_versions.architecture == "architecture-policy/v1"
}

# --- A denial anywhere reaches the top --------------------------------------

test_observability_denial_propagates if {
	silent := json.patch(compliant, [{
		"op": "replace",
		"path": "/modules/0/emits",
		"value": 0,
	}])
	not main.allow with input as silent
}

test_architecture_denial_propagates if {
	violating := json.patch(compliant, [{
		"op": "add",
		"path": "/modules/1/effective_imports/-",
		"value": "pyspark",
	}])
	not main.allow with input as violating
}

test_reasons_name_the_policy_that_refused if {
	# THE POINT OF COMPOSING RATHER THAN EVALUATING SEPARATELY: one verdict,
	# each reason attributed. Without the prefix an agent reading CI output has
	# to guess which control produced which line.
	silent := json.patch(compliant, [{
		"op": "replace",
		"path": "/modules/0/emits",
		"value": 0,
	}])
	expected := "observability: ingest/extract.py performs observable work but emits nothing"
	expected in main.deny with input as silent
}

test_architecture_reasons_are_attributed if {
	violating := json.patch(compliant, [{
		"op": "add",
		"path": "/modules/1/effective_imports/-",
		"value": "pyspark",
	}])
	expected := "architecture: ingest/fetch.py reaches pyspark -- acquisition must not run inside a Spark transformation"
	expected in main.deny with input as violating
}

test_both_policies_can_deny_at_once if {
	# Separate modules violating separate policies. BOTH reasons must surface,
	# or fixing one would reveal the other only on the next run -- the
	# fix-one-thing-per-CI-cycle loop that makes gates feel arbitrary.
	broken := json.patch(compliant, [
		{"op": "replace", "path": "/modules/0/emits", "value": 0},
		{"op": "add", "path": "/modules/1/effective_imports/-", "value": "pyspark"},
	])
	count(main.deny) >= 2 with input as broken
	not main.allow with input as broken
}

# --- Failing closed ----------------------------------------------------------

test_missing_inventory_denies if {
	not main.allow with input as {}
}

test_empty_module_list_denies if {
	# An empty ARRAY is a defined value in Rego, and only undefined is falsy, so
	# a presence check would not fire here. Both composed policies count.
	not main.allow with input as {"modules": []}
}
