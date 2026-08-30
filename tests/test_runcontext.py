# tests/test_runcontext.py
"""Run correlation across ingestion artifacts.

The digest chain already answers "what produced these bytes, and are they
intact" -- archive_sha256 links an extraction to the exact archive that caused
it, a causation edge proved by content rather than asserted by an id.

These tests cover what it could not: which orchestrated run wrote an artifact,
and by which actor. With six laptops running agents against one repository, an
artifact that cannot name its run cannot be traced back to a decision.

FIXTURES ARE SMALL ON PURPOSE. The property under test is that two records
written by one invocation share a run_id -- a string comparison. Proving it
against the real 283MB archive would re-download and re-extract for no
additional confidence. The real pipeline is exercised elsewhere, once.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import pytest

from spark_batch_pipeline.ingest.extract import ExtractionRecord, extract_member
from spark_batch_pipeline.ingest.fetch import IngestManifest, fetch_source
from spark_batch_pipeline.runcontext import (
    ACTOR_ENV,
    RUN_ID_ENV,
    RunContext,
    current_run,
    new_run_id,
    new_step_id,
)

MEMBER = "WDICSV.csv"
BODY = b"Country Name,Country Code,1960\nAruba,ABW,1.5\n" * 20
URL = "https://databank.example.org/data/download/WDI_CSV.zip"


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    path = tmp_path / "WDI_CSV.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(MEMBER, BODY)
    return path


class _Transport(httpx.BaseTransport):
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=self.payload)


# --- Identifier shape --------------------------------------------------------


def test_run_id_is_w3c_trace_id_shaped() -> None:
    """32 lowercase hex characters, exactly a W3C trace-id.

    The format is borrowed even though OpenTelemetry is not: hand-rolled ID
    formats are where correlation breaks, and adopting OTel later should be a
    rename rather than a migration.
    """
    run_id = new_run_id()

    assert len(run_id) == 32
    assert int(run_id, 16) >= 0, "must be hex"
    assert run_id == run_id.lower()


def test_step_id_is_w3c_span_id_shaped() -> None:
    step_id = new_step_id()

    assert len(step_id) == 16
    assert int(step_id, 16) >= 0


def test_ids_are_unique() -> None:
    assert len({new_run_id() for _ in range(1000)}) == 1000


# --- One run per process, even under concurrency ----------------------------


def test_run_context_is_stable_within_a_process() -> None:
    assert current_run() is current_run()


def test_run_context_is_stable_across_threads() -> None:
    """THE REASON THIS IS A MODULE CONSTANT AND NOT lru_cache.

    lru_cache is thread-safe against corruption but is not an
    initialise-exactly-once contract: two threads racing before the value is
    cached can each build a distinct object. For a run id that is precisely the
    bug the field exists to prevent -- artifacts from ONE invocation carrying
    two different run ids, so grouping fails exactly when concurrency makes it
    matter. This project drives extraction through a ThreadPoolExecutor.
    """
    with ThreadPoolExecutor(max_workers=16) as pool:
        ids = set(pool.map(lambda _: current_run().run_id, range(256)))

    assert len(ids) == 1


# --- Correlation across the two ingestion phases ----------------------------


def test_manifest_and_record_share_one_run_id(tmp_path: Path) -> None:
    """The property the field exists for: one invocation, one run id."""
    payload = tmp_path / "src.zip"
    with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(MEMBER, BODY)
    raw = payload.read_bytes()

    dest = tmp_path / "raw"
    with httpx.Client(transport=_Transport(raw), follow_redirects=True) as client:
        manifest = fetch_source(source_name="wdi", url=URL, dest_dir=dest, client=client)
    record = extract_member(dest / "WDI_CSV.zip", MEMBER, dest)

    assert manifest.run_id == record.run_id
    assert manifest.run_id == current_run().run_id
    assert manifest.actor == record.actor

    # And the causation edge is still proved by content, not asserted by an id.
    assert record.archive_sha256 == manifest.sha256
    assert manifest.sha256 == hashlib.sha256(raw).hexdigest()


def test_run_fields_survive_the_json_round_trip(archive: Path, tmp_path: Path) -> None:
    dest = tmp_path / "raw"
    written = extract_member(archive, MEMBER, dest)

    on_disk = json.loads(ExtractionRecord.path_for(dest / MEMBER).read_text())
    assert on_disk["run_id"] == written.run_id
    assert on_disk["actor"] == written.actor


# --- Unknown provenance is null, never fabricated ---------------------------


def test_records_without_run_fields_are_valid(archive: Path, tmp_path: Path) -> None:
    """A record written before these fields existed has UNKNOWN provenance.

    Forcing a value on a possibly-absent field is the documented anti-pattern:
    the writer is obliged to produce something, so it fabricates. null says
    "not recorded", which is true.
    """
    dest = tmp_path / "raw"
    extract_member(archive, MEMBER, dest)
    record_file = ExtractionRecord.path_for(dest / MEMBER)

    legacy = json.loads(record_file.read_text())
    del legacy["run_id"]
    del legacy["actor"]

    parsed = ExtractionRecord.model_validate_json(json.dumps(legacy))
    assert parsed.run_id is None
    assert parsed.actor is None


def test_explicit_null_is_accepted() -> None:
    """Omitted and null both mean "not recorded"; neither is an error."""
    payload = json.dumps(
        {
            "source_name": "wdi",
            "url": URL,
            "filename": "WDI_CSV.zip",
            "size_bytes": 1,
            "sha256": "a" * 64,
            "ingested_at": "2026-08-30T00:00:00Z",
            "run_id": None,
            "actor": None,
        }
    )

    parsed = IngestManifest.model_validate_json(payload)
    assert parsed.run_id is None


# --- Orchestrator override ---------------------------------------------------


def test_environment_names_the_run_and_actor(monkeypatch: pytest.MonkeyPatch) -> None:
    """When Airflow, a CI job, or a supervising agent already owns a
    correlation id, minting a local one would fragment the trace at exactly the
    boundary where it matters."""
    monkeypatch.setenv(RUN_ID_ENV, "0123456789abcdef0123456789abcdef")
    monkeypatch.setenv(ACTOR_ENV, "airflow:wdi_daily")

    # The module resolves at import, so construct directly to exercise the
    # same resolution a fresh process would perform.
    import importlib

    import spark_batch_pipeline.runcontext as rc

    reloaded = importlib.reload(rc)
    try:
        assert reloaded.current_run().run_id == "0123456789abcdef0123456789abcdef"
        assert reloaded.current_run().actor == "airflow:wdi_daily"
    finally:
        monkeypatch.undo()
        importlib.reload(rc)


def test_run_context_rejects_empty_values() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RunContext(run_id="", actor="host:x")
