# tests/test_acquire.py
"""The acquisition boundary as a single call.

The steps were correct before this module existed and nothing composed them, so
the right sequence lived in whichever ad-hoc script came next. These tests pin
the composition: the order, the handoff, and the property that keeps the
orchestrator choice reversible.

ORDER IS ASSERTED WITHIN ONE CALL, never across tests. Tests that depend on
each other are the documented anti-pattern -- and no ordering plugin is needed,
because what matters here is the sequence of events inside a single
invocation, which is a property of the code rather than of the runner.

The network is injected via MockTransport: a suite that needs the internet is
one that fails on a plane, and the property under test is ordering, not
throughput.
"""

from __future__ import annotations

import hashlib
import logging
import zipfile
from pathlib import Path

import httpx
import pytest

from spark_batch_pipeline.ingest import fetch
from spark_batch_pipeline.ingest.acquire import (
    RAW_ARTIFACT_VERSION,
    RawArtifact,
    acquire_source,
)
from spark_batch_pipeline.telemetry import EVENT_KEY, EventName

MEMBER = "WDICSV.csv"
BODY = b"Country Name,Country Code,1960\nAruba,ABW,1.5\n" * 20
URL = "https://databank.example.org/data/download/WDI_CSV.zip"


@pytest.fixture
def archive_bytes(tmp_path: Path) -> bytes:
    path = tmp_path / "src.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(MEMBER, BODY)
    return path.read_bytes()


@pytest.fixture
def client(archive_bytes: bytes) -> httpx.Client:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=archive_bytes)

    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)


def events(caplog: pytest.LogCaptureFixture) -> list[dict[str, object]]:
    return [record.__dict__[EVENT_KEY] for record in caplog.records if EVENT_KEY in record.__dict__]


def names(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [str(payload["name"]) for payload in events(caplog)]


# --- What the caller receives ------------------------------------------------


def test_returns_a_committed_readable_uri(client: httpx.Client, tmp_path: Path) -> None:
    """The file EXISTS when this returns. Nothing is deferred to a later action,
    which is the whole point of the boundary."""
    artifact = acquire_source(
        source_name="wdi",
        url=URL,
        member=MEMBER,
        dest_dir=tmp_path / "raw",
        client=client,
    )

    assert artifact.path.is_file()
    assert artifact.path.read_bytes() == BODY
    assert artifact.path.is_absolute(), "a relative path resolves against the reader's cwd"


def test_digests_identify_the_returned_bytes(client: httpx.Client, tmp_path: Path) -> None:
    artifact = acquire_source(
        source_name="wdi",
        url=URL,
        member=MEMBER,
        dest_dir=tmp_path / "raw",
        client=client,
    )

    assert artifact.member_sha256 == hashlib.sha256(BODY).hexdigest()
    assert artifact.member_sha256 != artifact.archive_sha256, "member is not the archive"
    assert artifact.size_bytes == len(BODY)


# --- The sequence ------------------------------------------------------------


def test_fetch_completes_before_extraction_starts(
    client: httpx.Client, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO):
        acquire_source(
            source_name="wdi",
            url=URL,
            member=MEMBER,
            dest_dir=tmp_path / "raw",
            client=client,
        )

    emitted = names(caplog)
    assert emitted.index(EventName.FETCH_PUBLISHED.value) < emitted.index(
        EventName.EXTRACTION_STARTED.value
    )


def test_handoff_fires_last(
    client: httpx.Client, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Everything upstream is committed when the handoff fires. Emitting it any
    earlier would announce a URI that is not yet safe to read."""
    with caplog.at_level(logging.INFO):
        acquire_source(
            source_name="wdi",
            url=URL,
            member=MEMBER,
            dest_dir=tmp_path / "raw",
            client=client,
        )

    assert names(caplog)[-1] == EventName.RAW_ARTIFACT_READY.value


def test_handoff_carries_the_uri(
    client: httpx.Client, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A consumer forced to reconstruct the path will drift from what was
    actually written."""
    with caplog.at_level(logging.INFO):
        artifact = acquire_source(
            source_name="wdi",
            url=URL,
            member=MEMBER,
            dest_dir=tmp_path / "raw",
            client=client,
        )

    ready = next(
        payload
        for payload in events(caplog)
        if payload["name"] == EventName.RAW_ARTIFACT_READY.value
    )
    assert ready["uri"] == artifact.uri
    assert ready["member_sha256"] == artifact.member_sha256


def test_second_call_is_cached_but_still_announces(
    client: httpx.Client, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A cached run must still hand off. A consumer waiting on the event would
    otherwise stall precisely when the pipeline had nothing to do."""
    dest = tmp_path / "raw"
    first = acquire_source(source_name="wdi", url=URL, member=MEMBER, dest_dir=dest, client=client)

    caplog.clear()
    with caplog.at_level(logging.INFO):
        second = acquire_source(
            source_name="wdi", url=URL, member=MEMBER, dest_dir=dest, client=client
        )

    assert second.member_sha256 == first.member_sha256
    emitted = names(caplog)
    assert EventName.FETCH_CACHE_HIT.value in emitted
    assert EventName.EXTRACTION_CACHE_HIT.value in emitted
    assert emitted[-1] == EventName.RAW_ARTIFACT_READY.value


# --- The failure path --------------------------------------------------------
# BACKOFF IS PATCHED, NOT WAITED ON. fetch retries four times with 1.5**attempt
# seconds of backoff, so each of these tests would spend ~8 real seconds
# sleeping. Retry tests are a well-documented way for a suite to quietly become
# minutes of CI wall-clock time.
#
# The alternative -- making the backoff configurable in production code -- was
# considered and rejected: that is test-only plumbing in a production
# signature. The monkeypatch is self-contained, auto-restored, and the test
# still exercises the full retry COUNT, which is the behaviour that matters.


@pytest.fixture
def instant_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fetch, "_sleep_backoff", lambda _attempt: None)


@pytest.fixture
def failing_client() -> httpx.Client:
    def boom(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated network failure")

    return httpx.Client(transport=httpx.MockTransport(boom))


def test_failure_still_raises(
    failing_client: httpx.Client, instant_backoff: None, tmp_path: Path
) -> None:
    """Telemetry observes; it does not swallow."""
    with pytest.raises(httpx.ConnectError):
        acquire_source(
            source_name="wdi",
            url=URL,
            member=MEMBER,
            dest_dir=tmp_path / "raw",
            client=failing_client,
        )


def test_failure_is_announced_with_its_cause(
    failing_client: httpx.Client,
    instant_backoff: None,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A consumer waiting on the handoff must learn it will never come.

    fetch and extract each report their own failure; neither answers the
    question the ORCHESTRATOR owns -- did the sequence complete? Without this
    event a caller blocked on raw_artifact.ready waits forever with nothing
    explaining why. The observability policy caught the omission.

    `except Exception`, not BaseException: a Ctrl-C is not an acquisition
    failure worth alerting on, and catching it would make the process hard to
    interrupt.
    """
    with caplog.at_level(logging.INFO), pytest.raises(httpx.ConnectError):
        acquire_source(
            source_name="wdi",
            url=URL,
            member=MEMBER,
            dest_dir=tmp_path / "raw",
            client=failing_client,
        )

    emitted = names(caplog)
    assert EventName.ACQUISITION_FAILED.value in emitted
    assert EventName.RAW_ARTIFACT_READY.value not in emitted, "no handoff on failure"

    failure = next(
        payload
        for payload in events(caplog)
        if payload["name"] == EventName.ACQUISITION_FAILED.value
    )
    assert failure["error.type"] == "ConnectError", (
        "the OTel spec attribute name is what reaches a backend, not the Python field name"
    )
    assert failure["outcome"] == "failure"
    # How long it ran BEFORE failing: four retries with backoff is a very
    # different incident from an immediate refusal.
    assert isinstance(failure["duration"], float)


# --- The property that keeps the orchestrator reversible ---------------------


def test_module_imports_no_orchestrator() -> None:
    """THE LOAD-BEARING PROPERTY. Dagster was chosen, and this module must stay
    callable without it -- that is what makes switching orchestrators a rewrite
    of a thin asset definition rather than of the pipeline.

    Asserted against the SOURCE, not sys.modules: dagster is absent from this
    environment by policy, so an import check would pass for the wrong reason
    and keep passing if someone added the import.
    """
    source = Path(acquire_source.__code__.co_filename).read_text()
    offenders = [
        line
        for line in source.splitlines()
        if line.startswith(("import ", "from ")) and "dagster" in line
    ]

    assert not offenders, f"orchestrator imported: {offenders}"


def test_artifact_contract_is_versioned(tmp_path: Path) -> None:
    """It crosses a layer boundary, so its shape is an interface."""
    artifact = RawArtifact(
        uri=str(tmp_path / "x.csv"),
        member_sha256="a" * 64,
        archive_sha256="b" * 64,
        size_bytes=1,
    )

    assert artifact.schema_version == RAW_ARTIFACT_VERSION
