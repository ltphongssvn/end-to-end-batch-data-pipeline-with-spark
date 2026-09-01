# src/spark_batch_pipeline/ingest/policy.py
"""Policy Enforcement Point for archive extraction.

THE RULES ARE NOT HERE. They live in policies/extraction/extraction.rego and are
evaluated by OPA. This module builds the decision input, asks once, and enforces
the answer.

WHY THE SPLIT
The limits were previously if-statements in this file. That works for one
consumer and fails for several: the curated and serving layers, the EEA CO2
ingestion, and any downstream agent need the same rules, and each would
otherwise reimplement them slightly differently -- which is how a limit ends up
being 4 GiB in one place and 4 GB in another. Rego owns the rules, OPA the
evaluation, this module the execution, and the decision record the evidence.

PDP ASKED ONCE, PEP ENFORCES CONTINUOUSLY.
The binding limit is a byte counter running per 8 MiB chunk. Asking OPA 25 times
per member would spend seconds re-deriving constants that never changed, so the
decision is fetched once and its LIMITS are applied while streaming. That is the
standard decision/enforcement boundary: OPA decides, it does not enforce.

WHY `opa eval` AND NOT A SERVER.
A sidecar or daemon is the right pattern for a service handling many requests;
this is a batch job that runs and exits. Requiring a running OPA on six laptops
and in CI would add an operational dependency to a pipeline that currently needs
none. A subprocess costs 50-200ms against an extraction that already takes
0.7s -- noise. opa is pinned in mise.toml alongside every other tool.

FAIL CLOSED. A missing binary, a malformed response, an unparseable decision:
each raises. A policy engine that cannot answer must never be read as "allowed".
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Final

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    NonNegativeFloat,
    NonNegativeInt,
)

# Where the policy lives, resolved from this file rather than the working
# directory: the pipeline runs from the repo root, from a git hook, and from
# pytest, and only one of those has a predictable cwd.
POLICY_DIR: Final = Path(__file__).resolve().parents[3] / "policies"

# The annotated entrypoint in extraction.rego. Declared there as metadata so the
# policy states its own interface; named here because a query needs a string.
DECISION_QUERY: Final = "data.extraction.decision"

# RESOLVED ONCE, THEN EXECUTED BY ABSOLUTE PATH.
#
# Calling shutil.which("opa") to check existence and then
# subprocess.run(["opa", ...]) to execute resolves the name TWICE, so the
# check guarantees nothing about what actually runs. CVE-2026-32015 is that
# exact bug: an allowlist of binary NAMES was bypassed by controlling PATH, so
# a trojan with an allowlisted name ran despite the validation.
#
# Resolving at import and passing the absolute path means the binary that was
# checked is the binary that runs. It also satisfies ruff S607, which exists
# for this reason rather than as a style preference.
_OPA: Final = shutil.which("opa")

_EVAL_TIMEOUT_SECONDS: Final = 30


class PolicyViolationError(Exception):
    """An archive or member was refused, before or during extraction.

    A distinct type, not ValueError: a policy refusal is a security decision a
    caller may want to handle, alert on, or quarantine differently from a
    corrupt download.
    """


class PolicyUnavailableError(Exception):
    """The policy could not be evaluated.

    Deliberately NOT a subclass of PolicyViolationError, and deliberately not
    swallowed. "The engine is missing" and "the archive is hostile" are
    different operational situations, and only one of them is fixed by
    installing something. Both stop the extraction.
    """


class DecisionLimits(BaseModel):
    """The limits the policy applied, as returned by OPA.

    Validated rather than trusted: the policy is a separate artifact that can be
    edited independently, so its output crosses a boundary into this process and
    is checked like any other external input.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    # NON-NEGATIVE, NOT POSITIVE, AND THAT DISTINCTION IS A BUG FIX.
    #
    # A DECISION MODEL MUST BE ABLE TO REPRESENT EVERY DECISION THE POLICY CAN
    # PRODUCE. These were PositiveInt, which made zero unrepresentable -- but
    # zero is a legitimate policy stance: "no member of this kind is permitted
    # at all". The policy correctly denied such a request and then this model
    # rejected the denial, turning a clean PolicyViolationError into a
    # ValidationError.
    #
    # Failing closed either way, so nothing unsafe happened -- but the failure
    # was reported as an engine fault rather than a refusal, and the
    # extraction.denied event never fired. The audit trail vanished exactly
    # when something was refused, which is when it matters most.
    #
    # An over-strict constraint on an OUTPUT is not extra safety; it is the
    # enforcement point disagreeing with the policy about what is expressible.
    max_member_bytes: NonNegativeInt
    max_total_bytes: NonNegativeInt
    max_members: NonNegativeInt
    max_compression_ratio: NonNegativeFloat
    allowed_methods: tuple[int, ...]
    free_space_headroom: NonNegativeFloat
    required_digest: str


class ExtractionDecision(BaseModel):
    """One authorization decision, suitable for an audit record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allow: bool
    policy_version: str = Field(min_length=1)
    reasons: tuple[str, ...]
    limits: DecisionLimits

    def raise_if_denied(self, member: str) -> None:
        """Refuse, naming every reason.

        All reasons, not the first: fixing one at a time when three apply is how
        an operator concludes the gate is arbitrary.
        """
        if not self.allow:
            joined = "; ".join(sorted(self.reasons))
            raise PolicyViolationError(f"policy denied {member!r}: {joined}")


# The seam. A callable taking the decision input as JSON and returning OPA's
# stdout, so a test can supply a fake instead of patching subprocess.
#
# INJECTED RATHER THAN MONKEYPATCHED, matching how fetch_source takes an
# httpx.Client. Patching subprocess.run reaches the stdlib module object every
# other module shares -- pytest's own docs warn that patching stdlib can break
# pytest itself -- and it couples the test to HOW the engine is invoked rather
# than to what it returns. That coupling is the documented PEP pitfall.
type DecisionRunner = Callable[[str], str]


def _run_opa(payload: str) -> str:
    """Invoke the pinned opa binary and return its stdout.

    Every failure mode raises: a policy engine that cannot answer must never be
    read as "allowed".
    """
    if _OPA is None:
        raise PolicyUnavailableError(
            "opa is not installed; run 'mise install' to get the pinned version"
        )

    try:
        # S603 acknowledged per-site, not disabled project-wide: argv is a LIST so
        # no shell is involved, and every element is a module constant or a path
        # resolved above. The rule stays enabled so the next subprocess call that
        # DOES take user input is flagged rather than lost in a global ignore.
        completed = subprocess.run(  # noqa: S603
            [
                _OPA,
                "eval",
                "--format",
                "json",
                "--data",
                str(POLICY_DIR),
                "--stdin-input",
                DECISION_QUERY,
            ],
            input=payload,
            capture_output=True,
            text=True,
            check=False,
            timeout=_EVAL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise PolicyUnavailableError(f"opa eval timed out after {_EVAL_TIMEOUT_SECONDS}s") from exc

    if completed.returncode != 0:
        raise PolicyUnavailableError(f"opa eval failed:\n{completed.stderr.strip()}")

    return completed.stdout


def evaluate(
    decision_input: dict[str, object], *, runner: DecisionRunner | None = None
) -> ExtractionDecision:
    """Ask the policy engine for a decision. Raises rather than defaulting to allow."""
    invoke = runner or _run_opa
    stdout = invoke(json.dumps(decision_input))

    try:
        payload = json.loads(stdout)
        value = payload["result"][0]["expressions"][0]["value"]
    except (json.JSONDecodeError, KeyError, IndexError) as exc:
        raise PolicyUnavailableError(
            f"could not read a decision from opa output:\n{stdout[:400]}"
        ) from exc

    # Validated, not trusted: the policy is a separately editable artifact, so
    # its output crosses a boundary into this process like any external input.
    return ExtractionDecision.model_validate(value)


def build_input(
    *,
    member_name: str,
    file_size: int,
    compress_size: int,
    compress_type: int,
    member_count: int,
    declared_total_bytes: int,
    claimed_compressed_bytes: int,
    archive_file_bytes: int,
    free_bytes: int,
    limits_override: dict[str, object] | None = None,
) -> dict[str, object]:
    """Assemble the decision input.

    Keyword-only and explicit: a positional call here would be nine integers in
    a row, and transposing two of them would silently change what the policy
    was asked.
    """
    decision_input: dict[str, object] = {
        "member": {
            "name": member_name,
            "file_size": file_size,
            "compress_size": compress_size,
            "compress_type": compress_type,
        },
        "archive": {
            "member_count": member_count,
            "declared_total_bytes": declared_total_bytes,
            "claimed_compressed_bytes": claimed_compressed_bytes,
            "file_bytes": archive_file_bytes,
        },
        "destination": {"free_bytes": free_bytes},
    }
    if limits_override:
        decision_input["limits"] = limits_override
    return decision_input


def enforce_while_writing(
    written: int, compress_size: int, member_name: str, limits: DecisionLimits
) -> None:
    """Abort mid-write once real output crosses a limit.

    THIS IS THE GUARANTEE, and it is why the limits are carried out of the
    decision rather than re-queried. Both quantities are MEASURED: `written` is
    what the decompressor actually produced, so an archive that lies in its
    header is caught here rather than after it has filled the disk.

    Pure and synchronous by design -- it runs once per 8 MiB chunk, so it must
    cost nothing beyond two comparisons.
    """
    if written > limits.max_member_bytes:
        raise PolicyViolationError(
            f"member {member_name!r} exceeded {limits.max_member_bytes:,} bytes "
            f"while extracting; aborted after {written:,}"
        )

    if compress_size > 0:
        ratio = written / compress_size
        if ratio > limits.max_compression_ratio:
            raise PolicyViolationError(
                f"member {member_name!r} reached a real compression ratio of "
                f"{ratio:.1f}x, limit is {limits.max_compression_ratio:g}x; "
                f"aborted after {written:,} bytes"
            )
