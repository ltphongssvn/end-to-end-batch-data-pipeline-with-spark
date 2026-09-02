# policies/architecture/architecture_test.rego
# Both directions for every rule. A boundary tested only where it fires cannot
# tell you whether it fires when it should not, and a gate that blocks
# legitimate work is one somebody deletes.
#
# FIXTURES ARE EXPLICIT LITERALS, NOT json.patch BY INDEX. A patch at
# /modules/2 depends on the current array order, so reordering the fixture
# would silently move the edit onto a different module while every test kept
# passing -- index drift is the documented failure mode of positional patching.
# Each case states the exact inventory it means.

package architecture_test

import rego.v1

import data.architecture

# The real shape: ingest is Spark-free, session.py owns Spark.
clean_extract := {
	"path": "ingest/extract.py",
	"effective_imports": ["hashlib", "pathlib", "pydantic", "zipfile"],
}

clean_fetch := {
	"path": "ingest/fetch.py",
	"effective_imports": ["hashlib", "httpx", "pydantic"],
}

clean_atomicio := {
	"path": "atomicio.py",
	"effective_imports": ["fcntl", "os", "pathlib"],
}

spark_owner := {"path": "session.py", "effective_imports": ["delta", "pyspark"]}

locked_ok := {"protobuf": "7.36.0", "pyspark": "4.0.4", "dagster-pipes": "1.13.19"}

valid_inventory := {
	"modules": [clean_extract, clean_fetch, clean_atomicio, spark_owner],
	"locked_packages": locked_ok,
}

# --- The happy path ----------------------------------------------------------

test_current_codebase_is_allowed if {
	architecture.allow with input as valid_inventory
}

test_no_reasons_when_satisfied if {
	count(architecture.deny) == 0 with input as valid_inventory
}

test_session_may_own_spark if {
	# Spark is not banned, it is PLACED. Without this the policy could pass by
	# forbidding Spark everywhere, which would block the pipeline entirely.
	architecture.allow with input as {"modules": [spark_owner]}
}

test_decision_carries_policy_version if {
	decision := architecture.decision with input as valid_inventory
	decision.policy_version == "architecture-policy/v1"
	decision.allow == true
}

# --- The boundary ------------------------------------------------------------

test_spark_in_ingest_denies if {
	# The failure this exists to prevent: acquisition inside a transformation,
	# where speculative execution can run a 283MB download twice by design.
	violating := {"modules": [
		{"path": "ingest/extract.py", "effective_imports": ["pyspark", "zipfile"]},
		spark_owner,
	]}
	not architecture.allow with input as violating
}

test_spark_in_ingest_explains_why if {
	violating := {"modules": [{
		"path": "ingest/extract.py",
		"effective_imports": ["pyspark"],
	}]}
	expected := "ingest/extract.py reaches pyspark -- acquisition must not run inside a Spark transformation"
	expected in architecture.deny with input as violating
}

test_transitive_reach_denies if {
	# THE REASON THE CLOSURE EXISTS. A module that imports session.py, which
	# imports pyspark, has the same dependency as one importing it directly --
	# and a flat scan of direct imports would see nothing at all.
	violating := {"modules": [{
		"path": "ingest/fetch.py",
		"effective_imports": ["httpx", "pyspark"],
	}]}
	not architecture.allow with input as violating
}

test_delta_in_ingest_denies if {
	violating := {"modules": [{
		"path": "atomicio.py",
		"effective_imports": ["delta", "os"],
	}]}
	not architecture.allow with input as violating
}

test_spark_outside_its_owner_denies if {
	# Not in the ingest layer, still a violation: a second module building
	# sessions is boundary erosion even where acquisition is not involved.
	violating := {"modules": [
		spark_owner,
		{"path": "curate/transform.py", "effective_imports": ["pyspark"]},
	]}
	not architecture.allow with input as violating
}

test_new_module_without_spark_is_fine if {
	# The negative case: adding a module is not itself a violation, or the
	# policy would block every future feature.
	added := {"modules": [
		clean_extract,
		spark_owner,
		{"path": "curate/schema.py", "effective_imports": ["pydantic"]},
	]}
	architecture.allow with input as added
}

# --- Input completeness ------------------------------------------------------
# An inventory that failed to generate must FAIL the gate. A rule referencing a
# missing field is undefined and contributes no denial, so without these a
# broken generator would look exactly like a compliant codebase.

test_missing_inventory_denies if {
	not architecture.allow with input as {}
}

test_empty_module_list_denies if {
	# An empty ARRAY is a defined value in Rego and only undefined is falsy, so
	# `not input.modules` never fires here. Counting is the check.
	not architecture.allow with input as {"modules": []}
}

test_entry_without_effective_imports_denies if {
	not architecture.allow with input as {"modules": [{"path": "ingest/fetch.py"}]}
}

# --- The lists themselves ----------------------------------------------------

test_every_forbidden_dependency_states_a_reason if {
	# A denial an operator cannot explain is one they will bypass.
	every dependency, why in architecture.forbidden_in_ingest {
		count(dependency) > 0
		count(why) > 0
	}
}

test_ingest_layer_is_not_empty if {
	# A vacuous layer would make every boundary rule pass trivially.
	count(architecture.ingest_layer) > 0
}

test_spark_owners_is_not_empty if {
	# An empty owner list would forbid Spark everywhere, which is not a
	# boundary but a shutdown.
	count(architecture.spark_owners) > 0
}

# --- The lockfile, which is where the real risk lives -----------------------

test_orchestrator_in_lockfile_denies if {
	# THE CASE THE RESOLVER DID NOT CATCH. `uv add dagster` with the protobuf
	# constraint in place did not fail: uv held protobuf at 7.x and satisfied
	# it by installing dagster 1.3.10, a 2023 release. uv documents this --
	# "instead of failing, the resolver will pick an older version without the
	# bound, circumventing the bound". A silent three-year backslide looks like
	# success, so presence is the check, not version.
	polluted := json.patch(valid_inventory, [{
		"op": "add",
		"path": "/locked_packages/dagster",
		"value": "1.3.10",
	}])
	not architecture.allow with input as polluted
}

test_orchestrator_reason_names_the_version if {
	polluted := json.patch(valid_inventory, [{
		"op": "add",
		"path": "/locked_packages/dagster",
		"value": "1.3.10",
	}])
	expected := "uv.lock contains dagster (1.3.10) -- the orchestrator belongs in its own code location"
	expected in architecture.deny with input as polluted
}

test_dagster_pipes_is_allowed if {
	# The positive case, and the whole point of the isolation: dagster-pipes
	# resolves to exactly one package with no dependencies, so the pipeline can
	# report to an orchestrator without hosting one.
	architecture.allow with input as valid_inventory
}

test_protobuf_downgrade_denies if {
	# The invariant the boundary exists to protect. Asserted directly so a
	# downgrade arriving through ANY transitive path is caught.
	downgraded := json.patch(valid_inventory, [{
		"op": "replace",
		"path": "/locked_packages/protobuf",
		"value": "6.33.6",
	}])
	not architecture.allow with input as downgraded
}

test_protobuf_7x_is_allowed if {
	current := json.patch(valid_inventory, [{
		"op": "replace",
		"path": "/locked_packages/protobuf",
		"value": "7.40.1",
	}])
	architecture.allow with input as current
}
