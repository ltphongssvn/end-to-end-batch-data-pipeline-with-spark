# tests/test_policy.py
"""The Policy Enforcement Point, not the policy.

THE RULES ARE TESTED IN REGO. policies/extraction/extraction_test.rego holds 28
cases at 100% coverage, asserting every deny rule in both directions. Repeating
them here would recreate exactly what moving policy to Rego eliminated: two
implementations of one rule, drifting apart. An earlier version of this file did
that, and it was deleted rather than ported.

WHAT IS TESTED HERE is the seam the policy cannot reach:

  input construction   the shape handed to OPA is the shape the policy expects.
                       A transposed field still evaluates -- against the wrong
                       question.
  enforcement          limits carried out of a decision are actually applied
                       per chunk. OPA decides; this module enforces, and only
                       this side can get that wrong.
  PDP unavailability   a missing binary, a timeout, or unparseable output must
                       fail CLOSED. The documented chaos test is "what happens
                       when the PDP is unreachable".

THE RUNNER IS INJECTED, NOT MONKEYPATCHED. Patching subprocess.run reaches the
stdlib module object every other module shares -- pytest's own docs warn that
patching stdlib can break pytest itself -- and it couples the test to HOW the
engine is invoked rather than what it returns. Injection is the same pattern
fetch_source uses for httpx.Client.

Inputs are built by a typed helper rather than unpacked from a dict: `**` into
a typed signature is uncheckable, and mypy said so 34 times.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from spark_batch_pipeline.ingest.policy import (
    DecisionLimits,
    ExtractionDecision,
    PolicyUnavailableError,
    PolicyViolationError,
    build_input,
    enforce_while_writing,
    evaluate,
)

LIMITS = DecisionLimits(
    max_member_bytes=4294967296,
    max_total_bytes=8589934592,
    max_members=64,
    max_compression_ratio=1032.0,
    allowed_methods=(0, 8),
    free_space_headroom=1.5,
    required_digest="sha256",
)


def real_archive_input(
    limits_override: dict[str, object] | None = None,
) -> dict[str, object]:
    """The real WDI archive, measured 2026-08-28.

    A typed helper rather than a dict unpacked with `**`: unpacking
    dict[str, object] into a typed signature cannot be checked, so every call
    site would silently lose verification.
    """
    return build_input(
        member_name="WDICSV.csv",
        file_size=198481686,
        compress_size=198511971,
        compress_type=8,
        member_count=6,
        declared_total_bytes=282801304,
        claimed_compressed_bytes=282844464,
        archive_file_bytes=282845220,
        free_bytes=500_000_000_000,
        limits_override=limits_override,
    )


def stub_runner(stdout: str):
    """A runner returning canned OPA output."""

    def _run(_payload: str) -> str:
        return stdout

    return _run


def decision_stdout(value: object) -> str:
    """Wrap a decision value in OPA's eval envelope."""
    return json.dumps({"result": [{"expressions": [{"value": value}]}]})


# --- Input construction: the contract with the policy ------------------------


def test_input_has_the_shape_the_policy_expects() -> None:
    """The policy denies on any missing field, so a shape change fails loudly
    instead of silently answering a different question."""
    payload = real_archive_input()

    assert set(payload) == {"member", "archive", "destination"}

    member = payload["member"]
    archive = payload["archive"]
    assert isinstance(member, dict)
    assert isinstance(archive, dict)
    assert set(member) == {"name", "file_size", "compress_size", "compress_type"}
    assert set(archive) == {
        "member_count",
        "declared_total_bytes",
        "claimed_compressed_bytes",
        "file_bytes",
    }


def test_limits_override_is_omitted_when_absent() -> None:
    """The policy merges input.limits over its defaults, so an absent override
    must not appear at all rather than as an empty object."""
    assert "limits" not in real_archive_input()


def test_limits_override_is_passed_through() -> None:
    assert real_archive_input({"max_members": 3})["limits"] == {"max_members": 3}


# --- Live evaluation: proves the wiring, not the rules -----------------------


def test_real_archive_is_allowed() -> None:
    decision = evaluate(real_archive_input())

    assert decision.allow
    assert decision.policy_version == "extraction-policy/v1"
    assert decision.reasons == ()


def test_decision_carries_the_limits_that_applied() -> None:
    """The audit answer to "why was this permitted", not merely "what happened"."""
    limits = evaluate(real_archive_input()).limits

    assert limits.max_compression_ratio == 1032.0
    assert limits.required_digest == "sha256"
    assert 8 in limits.allowed_methods


def test_denial_reaches_the_caller_with_reasons() -> None:
    """One rule end to end, proving the plumbing carries a denial. The rules
    themselves are covered in Rego."""
    decision = evaluate(real_archive_input({"max_members": 1}))

    assert not decision.allow
    assert decision.reasons != ()

    with pytest.raises(PolicyViolationError, match="policy denied"):
        decision.raise_if_denied("WDICSV.csv")


def test_denial_names_every_reason_not_just_the_first() -> None:
    """Fixing one violation at a time when three apply is how an operator
    concludes the gate is arbitrary."""
    decision = ExtractionDecision(
        allow=False,
        policy_version="extraction-policy/v1",
        reasons=("first problem", "second problem"),
        limits=LIMITS,
    )

    with pytest.raises(PolicyViolationError) as caught:
        decision.raise_if_denied("m.csv")

    assert "first problem" in str(caught.value)
    assert "second problem" in str(caught.value)


def test_allow_does_not_raise() -> None:
    ExtractionDecision(allow=True, policy_version="v1", reasons=(), limits=LIMITS).raise_if_denied(
        "m.csv"
    )


# --- Enforcement: what only this side can get wrong --------------------------


def test_streaming_abort_beats_a_lying_header() -> None:
    """THE GUARANTEE. file_size is a field IN the archive and therefore
    attacker-controlled, so an archive can declare 1MB and stream 100GB. Only
    the counter catches that, and only this module runs it."""
    small = LIMITS.model_copy(update={"max_member_bytes": 1024})

    with pytest.raises(PolicyViolationError, match="while extracting"):
        enforce_while_writing(5000, 100, "m.csv", small)


def test_streaming_abort_reports_where_it_stopped() -> None:
    small = LIMITS.model_copy(update={"max_member_bytes": 1024})

    with pytest.raises(PolicyViolationError, match="aborted after 2,048"):
        enforce_while_writing(2048, 100, "m.csv", small)


def test_real_ratio_is_computed_from_written_bytes() -> None:
    """Measured output over compressed input, so a forged header cannot help."""
    tight = LIMITS.model_copy(update={"max_compression_ratio": 10.0})

    with pytest.raises(PolicyViolationError, match="real compression ratio"):
        enforce_while_writing(1000, 10, "m.csv", tight)


def test_enforcement_passes_within_limits() -> None:
    enforce_while_writing(500, 100, "m.csv", LIMITS)


def test_zero_compress_size_skips_the_ratio_check() -> None:
    """A stored member would divide by zero otherwise."""
    enforce_while_writing(500, 0, "m.csv", LIMITS)


# --- PDP unavailability: must fail closed ------------------------------------


@pytest.mark.parametrize(
    "stdout",
    [
        pytest.param("not json", id="unparseable"),
        pytest.param("{}", id="no-result"),
        pytest.param('{"result": []}', id="empty-result"),
        pytest.param('{"result": [{"expressions": []}]}', id="no-expressions"),
    ],
)
def test_malformed_output_fails_closed(stdout: str) -> None:
    """An engine whose answer cannot be read must never be taken as "allowed"."""
    with pytest.raises(PolicyUnavailableError, match="could not read a decision"):
        evaluate(real_archive_input(), runner=stub_runner(stdout))


def test_engine_failure_propagates() -> None:
    """A runner that cannot reach the engine raises, and evaluate does not
    swallow it into a default."""

    def _unavailable(_payload: str) -> str:
        raise PolicyUnavailableError("opa is not installed")

    with pytest.raises(PolicyUnavailableError, match="not installed"):
        evaluate(real_archive_input(), runner=_unavailable)


def test_decision_with_unexpected_shape_is_rejected() -> None:
    """The policy is a separately editable artifact, so its output crosses a
    boundary into this process and is validated like any external input."""
    with pytest.raises(ValidationError):
        evaluate(
            real_archive_input(),
            runner=stub_runner(decision_stdout({"allow": True})),
        )


def test_stubbed_decision_round_trips() -> None:
    """Confirms the stub exercises the same parsing path as the real engine."""
    payload = decision_stdout(
        {
            "allow": True,
            "policy_version": "extraction-policy/v1",
            "reasons": [],
            "limits": LIMITS.model_dump(),
        }
    )

    decision = evaluate(real_archive_input(), runner=stub_runner(payload))

    assert decision.allow
    assert decision.limits == LIMITS


def test_unavailable_is_not_a_violation() -> None:
    """Different situations, and only one is fixed by installing something.
    Both stop the extraction."""
    assert not issubclass(PolicyUnavailableError, PolicyViolationError)
    assert not issubclass(PolicyViolationError, PolicyUnavailableError)
