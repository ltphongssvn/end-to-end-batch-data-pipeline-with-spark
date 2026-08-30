# policies/extraction/extraction_test.rego
# Tests live beside the policy they cover: easier to find, and the common
# practice in the OPA community. The _test package suffix is convention.
#
# EVERY RULE GETS A POSITIVE AND A NEGATIVE CASE. A deny rule tested only in
# its firing direction cannot tell you whether it fires when it should not, and
# an over-eager policy is how teams end up disabling the gate entirely.
#
# Each test starts from an input that MUST be allowed and perturbs exactly one
# field, so a failure names its own cause instead of leaving you to bisect.

package extraction_test

import rego.v1

import data.extraction

# Mirrors the REAL WDI archive, measured 2026-08-28. Using true values means a
# test failure is evidence about production, not about a fixture.
valid_input := {
	"member": {
		"name": "WDICSV.csv",
		"file_size": 198481686,
		"compress_size": 198511971,
		"compress_type": 8,
	},
	"archive": {
		"member_count": 6,
		"declared_total_bytes": 282801304,
		"claimed_compressed_bytes": 282844464,
		"file_bytes": 282845220,
	},
	"destination": {"free_bytes": 500000000000},
}

# --- The happy path ----------------------------------------------------------

test_real_archive_is_allowed if {
	extraction.allow with input as valid_input
}

test_real_archive_produces_no_reasons if {
	count(extraction.deny) == 0 with input as valid_input
}

test_decision_carries_policy_version if {
	decision := extraction.decision with input as valid_input
	decision.policy_version == "extraction-policy/v1"
	decision.allow == true
}

test_decision_carries_the_limits_that_applied if {
	decision := extraction.decision with input as valid_input
	decision.limits.max_compression_ratio == 1032
	decision.limits.required_digest == "sha256"
}

# --- Input completeness: the fail-open hole ----------------------------------
# THE MOST IMPORTANT TESTS IN THIS FILE. A rule referencing a missing field
# evaluates to UNDEFINED, and an undefined deny contributes nothing -- so
# without the completeness rules a truncated input would produce zero denials
# and therefore ALLOW. These prove the policy fails closed instead.

test_missing_member_field_denies if {
	broken := json.remove(valid_input, ["member/file_size"])
	not extraction.allow with input as broken
}

test_missing_archive_field_denies if {
	broken := json.remove(valid_input, ["archive/member_count"])
	not extraction.allow with input as broken
}

test_missing_destination_denies if {
	broken := json.remove(valid_input, ["destination/free_bytes"])
	not extraction.allow with input as broken
}

test_empty_input_denies if {
	not extraction.allow with input as {}
}

test_missing_field_reason_names_the_field if {
	broken := json.remove(valid_input, ["member/compress_type"])
	"input.member.compress_type is missing" in extraction.deny with input as broken
}

# --- Zip Slip, CWE-22 --------------------------------------------------------

test_absolute_path_denied if {
	bad := json.patch(valid_input, [{
		"op": "replace",
		"path": "/member/name",
		"value": "/etc/passwd",
	}])
	not extraction.allow with input as bad
}

test_traversal_denied if {
	bad := json.patch(valid_input, [{
		"op": "replace",
		"path": "/member/name",
		"value": "../escape.csv",
	}])
	not extraction.allow with input as bad
}

test_backslash_denied if {
	bad := json.patch(valid_input, [{
		"op": "replace",
		"path": "/member/name",
		"value": "a\\b.csv",
	}])
	not extraction.allow with input as bad
}

test_nested_path_denied if {
	bad := json.patch(valid_input, [{
		"op": "replace",
		"path": "/member/name",
		"value": "sub/dir.csv",
	}])
	not extraction.allow with input as bad
}

test_empty_name_denied if {
	bad := json.patch(valid_input, [{
		"op": "replace",
		"path": "/member/name",
		"value": "",
	}])
	not extraction.allow with input as bad
}

test_plain_name_allowed if {
	ok := json.patch(valid_input, [{
		"op": "replace",
		"path": "/member/name",
		"value": "WDICountry.csv",
	}])
	extraction.allow with input as ok
}

# --- Compression method ------------------------------------------------------

test_stored_allowed if {
	ok := json.patch(valid_input, [{
		"op": "replace",
		"path": "/member/compress_type",
		"value": 0,
	}])
	extraction.allow with input as ok
}

test_bzip2_denied if {
	bad := json.patch(valid_input, [{
		"op": "replace",
		"path": "/member/compress_type",
		"value": 12,
	}])
	not extraction.allow with input as bad
}

# --- Size limits -------------------------------------------------------------

test_oversized_member_denied if {
	bad := json.patch(valid_input, [{
		"op": "replace",
		"path": "/member/file_size",
		"value": 5000000000,
	}])
	not extraction.allow with input as bad
}

test_oversized_archive_denied if {
	bad := json.patch(valid_input, [{
		"op": "replace",
		"path": "/archive/declared_total_bytes",
		"value": 9000000000,
	}])
	not extraction.allow with input as bad
}

test_too_many_members_denied if {
	bad := json.patch(valid_input, [{
		"op": "replace",
		"path": "/archive/member_count",
		"value": 65,
	}])
	not extraction.allow with input as bad
}

test_member_count_at_the_limit_allowed if {
	ok := json.patch(valid_input, [{
		"op": "replace",
		"path": "/archive/member_count",
		"value": 64,
	}])
	extraction.allow with input as ok
}

# --- Compression ratio -------------------------------------------------------
# The threshold is DEFLATE's ceiling, so legitimately high ratios must PASS. A
# limit that rejects merely-compressible data is the one people switch off.

test_highly_compressible_data_allowed if {
	# 1027x: the measured ratio of 10MB of zero bytes. Extreme, and benign.
	ok := json.patch(valid_input, [
		{"op": "replace", "path": "/member/file_size", "value": 10485760},
		{"op": "replace", "path": "/member/compress_size", "value": 10210},
	])
	extraction.allow with input as ok
}

test_impossible_ratio_denied if {
	# Beyond anything DEFLATE can produce, so the header is lying.
	bad := json.patch(valid_input, [
		{"op": "replace", "path": "/member/file_size", "value": 1000000000},
		{"op": "replace", "path": "/member/compress_size", "value": 1000},
	])
	not extraction.allow with input as bad
}

# --- Flat bomb: overlapping entries ------------------------------------------

test_overlapping_entries_denied if {
	bad := json.patch(valid_input, [{
		"op": "replace",
		"path": "/archive/claimed_compressed_bytes",
		"value": 999999999999,
	}])
	not extraction.allow with input as bad
}

# --- Free space --------------------------------------------------------------

test_insufficient_free_space_denied if {
	bad := json.patch(valid_input, [{
		"op": "replace",
		"path": "/destination/free_bytes",
		"value": 1000,
	}])
	not extraction.allow with input as bad
}

test_headroom_is_enforced_not_just_size if {
	# Exactly the member size, which is NOT enough: 1.5x is required.
	bad := json.patch(valid_input, [{
		"op": "replace",
		"path": "/destination/free_bytes",
		"value": 198481686,
	}])
	not extraction.allow with input as bad
}

# --- Caller-supplied limits --------------------------------------------------

test_caller_can_tighten_limits if {
	tighter := json.patch(valid_input, [{
		"op": "add",
		"path": "/limits",
		"value": {"max_member_bytes": 1000},
	}])
	not extraction.allow with input as tighter
}

test_caller_limits_merge_with_defaults if {
	tighter := json.patch(valid_input, [{
		"op": "add",
		"path": "/limits",
		"value": {"max_members": 3},
	}])
	decision := extraction.decision with input as tighter

	# The override applies, and untouched defaults survive the merge.
	decision.limits.max_members == 3
	decision.limits.max_compression_ratio == 1032
}
