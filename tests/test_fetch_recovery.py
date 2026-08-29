# tests/test_fetch_recovery.py
"""Crash-recovery tests for the two-phase fetch commit.

Protocol: publish the artifact, then publish the manifest. The manifest is the
commit point, so a crash between phases must leave ORPHAN DATA -- a complete
file nothing references -- and the next run must redo the step rather than
trust or reject it.

No network: pytest-httpx serves every byte.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from pytest_httpx import HTTPXMock

from spark_batch_pipeline.atomicio import staging_path
from spark_batch_pipeline.ingest.fetch import IngestManifest, fetch_source

PAYLOAD = b"col_a,col_b\n1,2\n3,4\n" * 100
PAYLOAD_SHA = hashlib.sha256(PAYLOAD).hexdigest()
URL = "https://databank.example.org/data/download/WDI_CSV.zip"


@pytest.fixture(autouse=True)
def _no_backoff_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("spark_batch_pipeline.ingest.fetch._sleep_backoff", lambda _: None)


def test_crash_between_phases_leaves_recoverable_orphan(
    httpx_mock: HTTPXMock, tmp_path: Path
) -> None:
    """Artifact published, manifest never written: the next run must recover."""
    httpx_mock.add_response(content=PAYLOAD, is_reusable=True)

    fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)
    manifest_file = IngestManifest.path_for(tmp_path / "WDI_CSV.zip")
    manifest_file.unlink()  # crash after phase 1

    recovered = fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)

    assert recovered.sha256 == PAYLOAD_SHA
    assert manifest_file.is_file()


@pytest.mark.parametrize(
    "corruption",
    [
        pytest.param('{"source_name": "wdi", "url":', id="truncated-json"),
        pytest.param("", id="empty-file"),
        pytest.param("not json at all", id="garbage"),
        pytest.param("{}", id="valid-json-wrong-shape"),
    ],
)
def test_unreadable_manifest_is_treated_as_absent(
    httpx_mock: HTTPXMock, tmp_path: Path, corruption: str
) -> None:
    """A truncated manifest must trigger a re-fetch, not a crash.

    Before write_atomic, an interrupted manifest write left partial JSON and the
    next run died parsing it. Missing means "redo"; corrupt must mean the same,
    because a manifest that cannot be parsed carries no trustworthy claim.
    """
    httpx_mock.add_response(content=PAYLOAD, is_reusable=True)

    fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)
    manifest_file = IngestManifest.path_for(tmp_path / "WDI_CSV.zip")
    manifest_file.write_text(corruption)

    recovered = fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)

    assert recovered.sha256 == PAYLOAD_SHA
    assert IngestManifest.model_validate_json(manifest_file.read_text()) == recovered


def test_manifest_never_lands_partially(
    httpx_mock: HTTPXMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash DURING the manifest write must leave no manifest at all."""
    httpx_mock.add_response(content=PAYLOAD)
    manifest_file = IngestManifest.path_for(tmp_path / "WDI_CSV.zip")

    def _die_mid_write(target: Path, data: object, **kwargs: object) -> None:
        staging_path(target).write_text('{"source_name": "partial')
        raise OSError("simulated crash during manifest write")

    monkeypatch.setattr("spark_batch_pipeline.ingest.fetch.write_atomic", _die_mid_write)

    with pytest.raises(OSError, match="simulated crash"):
        fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)

    assert (tmp_path / "WDI_CSV.zip").read_bytes() == PAYLOAD, "phase 1 must survive"
    assert not manifest_file.exists(), "no manifest may exist under the real name"


def test_no_staged_files_survive_success(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    httpx_mock.add_response(content=PAYLOAD)

    fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)

    artifact = tmp_path / "WDI_CSV.zip"
    assert not staging_path(artifact).exists()
    assert not staging_path(IngestManifest.path_for(artifact)).exists()


def test_orphan_artifact_is_not_trusted_without_a_manifest(
    httpx_mock: HTTPXMock, tmp_path: Path
) -> None:
    """An artifact present with no manifest must be re-fetched, not accepted.

    Its bytes are unverified: nothing records what the source actually served,
    so treating it as complete would silently admit unattested data to the raw
    layer.
    """
    (tmp_path / "WDI_CSV.zip").write_bytes(b"unattested bytes of the right shape")
    httpx_mock.add_response(content=PAYLOAD)

    manifest = fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)

    assert manifest.sha256 == PAYLOAD_SHA
    assert (tmp_path / "WDI_CSV.zip").read_bytes() == PAYLOAD
