# tests/test_telemetry.py
"""Telemetry contract tests.

Instrumentation nobody verifies drifts: an attribute disappears, a type changes,
an event stops firing, and nothing notices until an incident needs it. The
remedy is the one used for API contracts -- define what the telemetry must look
like, then assert every emission conforms.

Three properties, and they are different claims:

  COMPLETENESS  every state transition emits. An operation that silently emits
                nothing is indistinguishable from one that never ran.
  CORRELATION   every event carries run_id and actor, or it joins to nothing
                and the rest of the payload is decoration.
  CORRECTNESS   the values are true. A dashboard built on wrong numbers is
                worse than no dashboard, because it is believed.

ASSERTIONS ARE AGAINST caplog.records AND THE STRUCTURED PAYLOAD, never
caplog.text. Formatted output carries timestamps, process ids and formatter
choices; a test whose real requirement is "this event fired with these fields"
should not break when someone changes a format string.

caplog captures through the root logger, which works here because the library
only attaches a NullHandler and never disables propagation. Application code
that replaces root handlers would break capture -- which is exactly why a
library must not configure logging.
"""

from __future__ import annotations

import json
import logging
import zipfile
from datetime import datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from spark_batch_pipeline.ingest.extract import extract_member
from spark_batch_pipeline.ingest.policy import PolicyViolationError
from spark_batch_pipeline.runcontext import current_run
from spark_batch_pipeline.telemetry import (
    EVENT_KEY,
    PIPELINE_EVENT_VERSION,
    EventName,
    Outcome,
    PipelineEvent,
    emit,
    event,
    timed,
)

BODY = b"Country Name,Country Code,1960\nAruba,ABW,1.5\n" * 40
MEMBER = "WDICSV.csv"


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    path = tmp_path / "WDI_CSV.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(MEMBER, BODY)
    return path


def captured(caplog: pytest.LogCaptureFixture) -> list[dict[str, object]]:
    """Every pipeline event among the captured records, in emission order."""
    return [record.__dict__[EVENT_KEY] for record in caplog.records if EVENT_KEY in record.__dict__]


def names(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [str(payload["name"]) for payload in captured(caplog)]


def find(caplog: pytest.LogCaptureFixture, name: EventName) -> dict[str, object]:
    return next(p for p in captured(caplog) if p["name"] == name.value)


# --- Completeness ------------------------------------------------------------


def test_successful_extraction_emits_the_full_sequence(
    archive: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The happy path is a story and every chapter must be present, in order."""
    with caplog.at_level(logging.INFO):
        extract_member(archive, MEMBER, tmp_path / "raw")

    assert names(caplog) == [
        EventName.EXTRACTION_STARTED.value,
        EventName.EXTRACTION_AUTHORIZED.value,
        EventName.EXTRACTION_VERIFIED.value,
        EventName.EXTRACTION_PUBLISHED.value,
    ]


def test_second_run_emits_only_a_cache_hit(
    archive: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Explains why a run took half a second instead of a minute -- otherwise
    indistinguishable from the work silently not happening."""
    dest = tmp_path / "raw"
    extract_member(archive, MEMBER, dest)

    caplog.clear()
    with caplog.at_level(logging.INFO):
        extract_member(archive, MEMBER, dest)

    assert names(caplog) == [EventName.EXTRACTION_CACHE_HIT.value]


def test_denial_emits_and_never_reports_success(
    archive: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The negative case matters as much as the positive: a refused extraction
    must not leave a success event behind."""
    with caplog.at_level(logging.INFO), pytest.raises(PolicyViolationError):
        extract_member(archive, MEMBER, tmp_path / "raw", limits_override={"max_members": 0})

    emitted = names(caplog)
    assert EventName.EXTRACTION_DENIED.value in emitted
    assert EventName.EXTRACTION_FAILED.value in emitted
    assert EventName.EXTRACTION_PUBLISHED.value not in emitted
    assert EventName.EXTRACTION_VERIFIED.value not in emitted


def test_denial_names_the_policy_that_refused(
    archive: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """ "Why was this refused" is unanswerable without the policy version."""
    with caplog.at_level(logging.INFO), pytest.raises(PolicyViolationError):
        extract_member(archive, MEMBER, tmp_path / "raw", limits_override={"max_members": 0})

    denial = find(caplog, EventName.EXTRACTION_DENIED)
    assert denial["policy_version"] == "extraction-policy/v1"
    assert "members" in str(denial["reason"])
    assert denial["outcome"] == Outcome.FAILURE.value


# --- Correlation -------------------------------------------------------------


def test_every_event_carries_correlation(
    archive: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """An event without run_id joins to nothing, which makes the rest of its
    payload decoration."""
    with caplog.at_level(logging.INFO):
        extract_member(archive, MEMBER, tmp_path / "raw")

    run = current_run()
    payloads = captured(caplog)
    assert payloads, "no events captured"

    for payload in payloads:
        assert payload["run_id"] == run.run_id
        assert payload["actor"] == run.actor
        assert payload["schema_version"] == PIPELINE_EVENT_VERSION


def test_all_events_of_one_run_share_a_run_id(
    archive: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO):
        extract_member(archive, MEMBER, tmp_path / "raw")

    assert len({payload["run_id"] for payload in captured(caplog)}) == 1


# --- Correctness -------------------------------------------------------------


def test_published_event_agrees_with_the_record(
    archive: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Telemetry that disagrees with the artifact is worse than none."""
    with caplog.at_level(logging.INFO):
        record = extract_member(archive, MEMBER, tmp_path / "raw")

    published = find(caplog, EventName.EXTRACTION_PUBLISHED)
    assert published["member_sha256"] == record.sha256
    assert published["archive_sha256"] == record.archive_sha256
    assert published["bytes_total"] == record.size_bytes
    assert published["crc32"] == record.crc32
    assert published["outcome"] == Outcome.SUCCESS.value


def test_verified_reports_bytes_actually_written(
    archive: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO):
        extract_member(archive, MEMBER, tmp_path / "raw")

    assert find(caplog, EventName.EXTRACTION_VERIFIED)["bytes_total"] == len(BODY)


def test_started_reports_why_work_was_needed(
    archive: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """ABSENT and CORRUPT mean very different things to an operator."""
    with caplog.at_level(logging.INFO):
        extract_member(archive, MEMBER, tmp_path / "raw")

    assert find(caplog, EventName.EXTRACTION_STARTED)["reason"] == "absent"


# --- The contract itself -----------------------------------------------------


def test_events_are_json_serializable(caplog: pytest.LogCaptureFixture) -> None:
    """A payload a log shipper cannot serialize is one nobody receives."""
    with caplog.at_level(logging.INFO):
        emit(event(EventName.EXTRACTION_STARTED, member=MEMBER))

    json.dumps(captured(caplog)[0])


def test_absent_fields_are_omitted_not_null(caplog: pytest.LogCaptureFixture) -> None:
    """A log store charges for nulls, and absent and null mean the same here."""
    with caplog.at_level(logging.INFO):
        emit(event(EventName.EXTRACTION_STARTED, member=MEMBER))

    assert "duration" not in captured(caplog)[0]


def test_payload_cannot_collide_with_logrecord(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """extra unpacks into LogRecord.__dict__ and Python's docs warn the keys
    must not clash with the logging system's. Spreading fields would collide on
    name, module and args -- a KeyError inside the logging call, taking down the
    process the telemetry exists to observe. One namespaced key makes that
    impossible, and record.name stays the logger's own."""
    with caplog.at_level(logging.INFO):
        emit(event(EventName.EXTRACTION_STARTED, member=MEMBER))

    record = caplog.records[0]
    assert record.name == "spark_batch_pipeline.telemetry"
    assert record.__dict__[EVENT_KEY]["name"] == EventName.EXTRACTION_STARTED.value


def test_invalid_event_is_rejected_before_emission() -> None:
    """Validated at construction, so a malformed event never reaches a log."""
    with pytest.raises(ValidationError):
        # The REAL field name. With the old name this raised via
        # extra=forbid on an unknown key, so it passed whether or not
        # the ge=0 constraint existed -- right outcome, wrong cause.
        event(EventName.EXTRACTION_STARTED, duration=-1)

    with pytest.raises(ValidationError):
        event(EventName.EXTRACTION_STARTED, unknown_field="x")


def test_naive_timestamp_is_rejected() -> None:
    """A naive timestamp cannot order events from machines in two zones."""
    with pytest.raises(ValidationError):
        PipelineEvent.model_validate(
            {
                "name": EventName.EXTRACTION_STARTED,
                "occurred_at": datetime.now(),  # noqa: DTZ005 - naive IS the input under test
                "run_id": "a" * 32,
                "actor": "host:x",
            }
        )


def test_timed_reports_a_non_negative_duration() -> None:
    """perf_counter, not the wall clock: an NTP step backwards would produce a
    negative duration the model then rejects at the worst possible moment."""
    with timed() as elapsed:
        pass

    assert elapsed["duration"] >= 0

    # SECONDS, NOT MILLISECONDS, and this assertion is the guard on that.
    # OpenTelemetry states durations SHOULD use seconds, and migrated
    # http.server.duration (ms) to http.server.request.duration (s) to
    # align with Prometheus. A consumer reading 0.87 as milliseconds is
    # wrong by 1000x and silently so, which is why the unit is pinned by
    # a test rather than by a comment.
    assert elapsed["duration"] < 1.0, "an empty block cannot take a second"


def test_timed_records_duration_even_when_the_block_fails() -> None:
    """How long an operation ran before failing is the interesting part."""
    with pytest.raises(RuntimeError), timed() as elapsed:
        raise RuntimeError("boom")

    assert "duration" in elapsed


def test_library_stays_silent_until_asked() -> None:
    """A library must never configure logging: no basicConfig, no level, no
    handler beyond NullHandler. That is the application's decision, and
    replacing root handlers is what breaks a caller's log capture."""
    logger = logging.getLogger("spark_batch_pipeline.telemetry")

    assert any(isinstance(h, logging.NullHandler) for h in logger.handlers)
    assert logger.level == logging.NOTSET, "a library must not set a level"
    assert logger.propagate, "propagation is how a caller receives these events"
