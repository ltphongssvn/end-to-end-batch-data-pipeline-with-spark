# policies/extraction/extraction.rego
# Authorization policy for extracting a member from an untrusted archive.
#
# WHY THE POLICY LIVES HERE AND NOT IN PYTHON
# These rules were if-statements spread through policy.py. That works for one
# consumer and fails for several: the curated and serving layers, the EEA CO2
# ingestion, and any downstream agent need the same limits, and each would
# otherwise reimplement them slightly differently. Separating the artifact gives
# Rego the rules, OPA the evaluation, Python the execution, and the decision
# record the audit evidence.
#
# THIS FILE DECIDES; IT DOES NOT ENFORCE.
# OPA answers "may this member be extracted, and under which limits". Python
# applies those limits while streaming, because the binding check is a byte
# counter running once per 8MiB chunk -- asking a policy engine 25 times per
# member would spend seconds re-deriving constants that never changed. That is
# the standard PDP/PEP split, not a shortcut.
#
# LAYOUT: every deny clause is contiguous, helpers come first. Incremental rules
# scattered through a file are how a reader misses one, and a deny clause nobody
# notices is a rule that effectively does not exist.
#
# import rego.v1 is a no-op on OPA v1.0 and later, where if and contains are
# mandatory anyway. It is kept because this policy is meant to be consumed by
# downstream tasks that may pin a different OPA version.

# METADATA
# title: Archive extraction authorization
# description: |
#   Decides whether one member of an untrusted ZIP archive may be extracted,
#   and under which limits. Decides only; enforcement of the streaming byte
#   counter stays in the caller.
# authors:
#   - ltphongssvn
package extraction

import rego.v1

# Travels in every decision, so an audit reading a sidecar knows which rules
# authorized the extraction. Bump on any change of MEANING; a rule that only
# narrows what is already allowed keeps the version.
policy_version := "extraction-policy/v1"

# --- Limits ------------------------------------------------------------------
# Measured against the real archive on 2026-08-28, not guessed:
#   WDICSV.csv  198,481,686 uncompressed / 198,511,971 compressed  ratio 1.00
#   6 members, all ZIP_DEFLATED, 282,801,304 bytes uncompressed in total

default_limits := {
	# ~20x the largest real member: years of growth pass, while runaway
	# inflation is stopped long before it fills a volume.
	"max_member_bytes": 4294967296,
	"max_total_bytes": 8589934592,
	# Measured: 6 members. A bomb can be many small entries, not one large one.
	"max_members": 64,
	# 1032 is DEFLATE'S THEORETICAL CEILING, not a tuning choice. A single
	# deflate member cannot exceed it, so any lower threshold rejects data that
	# is merely very compressible: 10MB of zero bytes measures 1027.7x while
	# being entirely benign. A control that blocks valid input gets switched
	# off. Bombs beat 1032 only by recursion, which this pipeline never does,
	# or by overlapping entries, checked below.
	"max_compression_ratio": 1032,
	# STORED and DEFLATED cover every member the World Bank ships. BZIP2 and
	# LZMA are legitimate but reach far higher ratios, so they are opt-in.
	"allowed_methods": [0, 8],
	# Refuse when the volume would be left with less than this multiple of the
	# declared size. Filling a disk takes down the host, not just this job.
	"free_space_headroom": 1.5,
	# SHA-256 is the root of trust. CRC-32 is a transport check ZIP supplies
	# for free; collisions are trivial to construct, so it cannot attest that
	# content is what the source published.
	"required_digest": "sha256",
}

limits := object.union(default_limits, object.get(input, "limits", {}))

# --- Helpers -----------------------------------------------------------------

# Fields every later rule assumes exist. See the completeness denials below for
# why their absence must be a denial rather than silence.
required_member_fields := {"name", "file_size", "compress_size", "compress_type"}

required_archive_fields := {
	"member_count",
	"declared_total_bytes",
	"claimed_compressed_bytes",
	"file_bytes",
}

# Zip Slip, CWE-22. Rejected rather than silently trimmed to a basename:
# trimming neutralizes the traversal but lets two distinct members collapse onto
# one output name, so the archive still decides which write wins.
member_escapes if startswith(input.member.name, "/")

member_escapes if contains(input.member.name, "..")

member_escapes if contains(input.member.name, "\\")

member_escapes if contains(input.member.name, "/")

method_allowed if {
	some method in limits.allowed_methods
	method == input.member.compress_type
}

declared_ratio := input.member.file_size / input.member.compress_size if {
	input.member.compress_size > 0
}

# --- Denials -----------------------------------------------------------------
# One contiguous block. Each carries a human-readable reason, because a decision
# an operator cannot explain is one they will eventually bypass.

# INPUT COMPLETENESS FIRST, and these are the least obvious rules in the file.
#
# A Rego rule referencing a missing field evaluates to UNDEFINED, and an
# undefined deny contributes nothing. For an inverted rule that is backwards: a
# truncated or malformed input would produce zero denials and therefore ALLOW. A
# security policy that fails open on incomplete input is worse than none,
# because it looks like it is working.
deny contains reason if {
	some field in required_member_fields
	not field in object.keys(object.get(input, "member", {}))
	reason := sprintf("input.member.%s is missing", [field])
}

deny contains reason if {
	some field in required_archive_fields
	not field in object.keys(object.get(input, "archive", {}))
	reason := sprintf("input.archive.%s is missing", [field])
}

deny contains reason if {
	not "free_bytes" in object.keys(object.get(input, "destination", {}))
	reason := "input.destination.free_bytes is missing"
}

deny contains reason if {
	member_escapes
	reason := sprintf("member name escapes its directory: %q", [input.member.name])
}

deny contains reason if {
	input.member.name == ""
	reason := "member name is empty"
}

deny contains reason if {
	not method_allowed
	reason := sprintf(
		"compression method %v is not allowed (permitted: %v)",
		[input.member.compress_type, limits.allowed_methods],
	)
}

deny contains reason if {
	input.member.file_size > limits.max_member_bytes
	reason := sprintf(
		"member declares %v bytes, limit is %v",
		[input.member.file_size, limits.max_member_bytes],
	)
}

deny contains reason if {
	input.archive.declared_total_bytes > limits.max_total_bytes
	reason := sprintf(
		"archive declares %v bytes uncompressed, limit is %v",
		[input.archive.declared_total_bytes, limits.max_total_bytes],
	)
}

deny contains reason if {
	input.archive.member_count > limits.max_members
	reason := sprintf(
		"archive holds %v members, limit is %v",
		[input.archive.member_count, limits.max_members],
	)
}

deny contains reason if {
	declared_ratio > limits.max_compression_ratio
	reason := sprintf(
		"declared compression ratio %vx exceeds %v",
		[declared_ratio, limits.max_compression_ratio],
	)
}

# FLAT BOMB DETECTION. A non-recursive bomb points many central-directory
# entries at one shared kernel of compressed data, so the archive claims more
# compressed content than the file physically holds. That overlap is how a bomb
# exceeds DEFLATE's ceiling without nesting.
deny contains reason if {
	input.archive.claimed_compressed_bytes > input.archive.file_bytes
	reason := sprintf(
		"members claim %v compressed bytes but the file is %v; entries overlap",
		[input.archive.claimed_compressed_bytes, input.archive.file_bytes],
	)
}

deny contains reason if {
	required := input.member.file_size * limits.free_space_headroom
	input.destination.free_bytes < required
	reason := sprintf(
		"needs about %v bytes free with headroom, only %v available",
		[round(required), input.destination.free_bytes],
	)
}

# --- Decision ----------------------------------------------------------------
# DEFAULT DENY: an undefined rule denies, so a policy bug fails closed.

default allow := false

allow if count(deny) == 0

# What an audit reads. Carries the limits that applied, so a sidecar answers
# "why was this allowed" rather than merely "what happened".
#
# ANNOTATED AS THE ENTRYPOINT for two reasons that are not style. `opa build -O`
# eliminates documents nothing references, so an unannotated entrypoint can be
# optimized out of a bundle, which then answers "undefined" for the only query
# that matters. And it moves the interface into the artifact: without it,
# "query data.extraction.decision" lives only in whichever Python happens to
# ask, and the next consumer has to read that code to discover it.

# METADATA
# entrypoint: true
# description: |
#   Authorization decision for extracting one archive member. Returns allow,
#   the policy version that decided, the reasons for any denial, and the limits
#   that applied -- so a caller can act on the verdict and record why it was
#   permitted.
decision := {
	"allow": allow,
	"policy_version": policy_version,
	"reasons": deny,
	"limits": limits,
}
