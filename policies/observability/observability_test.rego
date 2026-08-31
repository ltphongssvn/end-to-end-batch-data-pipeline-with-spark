# policies/observability/observability_test.rego
# Every rule exercised in both directions. A deny tested only where it fires
# cannot tell you whether it fires when it should not, and a gate that cries
# wolf is a gate someone switches off.
#
# `not observability.allow` is meaningful only because the policy declares
# `default allow := false`. An unmet condition in Rego yields UNDEFINED rather
# than false, so without that default these assertions would be testing the
# absence of a value rather than a denial.

package observability_test

import rego.v1

import data.observability

# Mirrors the real inventory: two instrumented modules, one exempt.
valid_inventory := {"modules": [
	{
		"path": "ingest/fetch.py",
		"emits": 6,
		"has_success_event": true,
		"has_failure_event": true,
	},
	{
		"path": "ingest/extract.py",
		"emits": 7,
		"has_success_event": true,
		"has_failure_event": true,
	},
	{
		"path": "telemetry.py",
		"emits": 0,
		"has_success_event": false,
		"has_failure_event": false,
	},
]}

unclassified_entry := {
	"path": "brand_new.py",
	"emits": 0,
	"has_success_event": false,
	"has_failure_event": false,
}

# --- The happy path ----------------------------------------------------------

test_current_codebase_is_allowed if {
	observability.allow with input as valid_inventory
}

test_no_reasons_when_satisfied if {
	count(observability.deny) == 0 with input as valid_inventory
}

test_decision_carries_policy_version if {
	decision := observability.decision with input as valid_inventory
	decision.policy_version == "observability-policy/v1"
	decision.allow == true
}

# --- Input completeness ------------------------------------------------------
# An inventory that failed to generate must FAIL the gate, not pass it. A rule
# referencing a missing field is undefined and contributes no denial, so
# without these a broken generator would look exactly like success.

test_missing_inventory_denies if {
	not observability.allow with input as {}
}

test_empty_module_list_denies if {
	not observability.allow with input as {"modules": []}
}

test_entry_without_path_denies if {
	not observability.allow with input as {"modules": [{"emits": 1}]}
}

test_entry_without_emits_denies if {
	not observability.allow with input as {"modules": [{"path": "ingest/fetch.py"}]}
}

# --- Minimum instrumentation -------------------------------------------------

test_silent_instrumented_module_denies if {
	silent := json.patch(valid_inventory, [{
		"op": "replace",
		"path": "/modules/0/emits",
		"value": 0,
	}])
	not observability.allow with input as silent
}

test_silence_reason_names_the_module if {
	silent := json.patch(valid_inventory, [{
		"op": "replace",
		"path": "/modules/0/emits",
		"value": 0,
	}])
	expected := "ingest/fetch.py performs observable work but emits nothing"
	expected in observability.deny with input as silent
}

test_missing_success_outcome_denies if {
	partial := json.patch(valid_inventory, [{
		"op": "replace",
		"path": "/modules/0/has_success_event",
		"value": false,
	}])
	not observability.allow with input as partial
}

test_missing_failure_outcome_denies if {
	partial := json.patch(valid_inventory, [{
		"op": "replace",
		"path": "/modules/1/has_failure_event",
		"value": false,
	}])
	not observability.allow with input as partial
}

# --- Classification is the change control ------------------------------------

test_unclassified_module_denies if {
	added := json.patch(valid_inventory, [{
		"op": "add",
		"path": "/modules/-",
		"value": unclassified_entry,
	}])
	not observability.allow with input as added
}

test_unclassified_reason_says_what_to_do if {
	added := json.patch(valid_inventory, [{
		"op": "add",
		"path": "/modules/-",
		"value": unclassified_entry,
	}])
	expected := "brand_new.py is neither instrumented nor exempt; classify it in the policy"
	expected in observability.deny with input as added
}

test_exempt_module_may_be_silent if {
	# The positive case for the exemption list: silence is allowed when it has
	# been justified, and only then.
	exempt_only := {"modules": [{
		"path": "valuetypes.py",
		"emits": 0,
		"has_success_event": false,
		"has_failure_event": false,
	}]}
	observability.allow with input as exempt_only
}

test_exempt_module_need_not_report_outcomes if {
	# Outcome rules apply only to instrumented modules. Applying them to exempt
	# ones would make the exemption meaningless.
	exempt_only := {"modules": [{
		"path": "atomicio.py",
		"emits": 0,
		"has_success_event": false,
		"has_failure_event": false,
	}]}
	count(observability.deny) == 0 with input as exempt_only
}

test_every_exemption_carries_a_reason if {
	# A list without governance is drift with better branding. `every` states
	# universal quantification explicitly: EVERY entry must justify itself, so
	# an exemption cannot be slipped in blank.
	every path, reason in observability.exempt {
		count(path) > 0
		count(reason) > 0
	}
}
