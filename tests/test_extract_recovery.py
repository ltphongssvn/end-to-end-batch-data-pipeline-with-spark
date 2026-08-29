# tests/test_extract_recovery.py
"""Crash-recovery tests for the two-phase extraction commit.

The protocol is: publish data, then publish the sidecar. The sidecar is the
commit point, so a crash between the phases must leave ORPHAN DATA -- a
complete file that nothing references -- and the next run must simply redo the
step. These tests simulate each crash window directly.

Nothing here needs the real 198MB archive.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from spark_batch_pipeline.atomicio import staging_path
from spark_batch_pipeline.ingest.extract import ExtractionRecord, extract_member

BODY = b"Country Name,Country Code,1960\nAruba,ABW,1.5\n" * 40
MEMBER = "WDICSV.csv"


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    path = tmp_path / "WDI_CSV.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(MEMBER, BODY)
    return path


def test_crash_between_phases_leaves_recoverable_orphan(archive: Path, tmp_path: Path) -> None:
    """Data published, sidecar never written: the next run must recover.

    This is the exact window the two-phase ordering is designed around. The
    data file is complete and correct; nothing references it. Re-running must
    produce a valid record rather than trusting or rejecting the orphan.
    """
    dest = tmp_path / "raw"
    extract_member(archive, MEMBER, dest)

    record_file = ExtractionRecord.path_for(dest / MEMBER)
    record_file.unlink()  # simulate the crash after phase 1

    recovered = extract_member(archive, MEMBER, dest)

    assert (dest / MEMBER).read_bytes() == BODY
    assert record_file.is_file()
    assert recovered.size_bytes == len(BODY)


@pytest.mark.parametrize(
    "corruption",
    [
        pytest.param('{"archive": "x", "member":', id="truncated-json"),
        pytest.param("", id="empty-file"),
        pytest.param("not json at all", id="garbage"),
        pytest.param("{}", id="valid-json-wrong-shape"),
    ],
)
def test_unreadable_sidecar_is_treated_as_absent(
    archive: Path, tmp_path: Path, corruption: str
) -> None:
    """A truncated sidecar must not be fatal.

    Before write_atomic, a crash mid-write could leave partial JSON, and the
    next run died parsing it. Missing means "redo"; corrupt must mean the same
    thing, because a sidecar that cannot be parsed carries no trustworthy claim.
    """
    dest = tmp_path / "raw"
    extract_member(archive, MEMBER, dest)

    record_file = ExtractionRecord.path_for(dest / MEMBER)
    record_file.write_text(corruption)

    recovered = extract_member(archive, MEMBER, dest)

    assert recovered.crc32 != 0
    assert ExtractionRecord.model_validate_json(record_file.read_text()) == recovered


def test_sidecar_is_published_atomically(archive: Path, tmp_path: Path) -> None:
    """No staging file may survive either phase of a successful run."""
    dest = tmp_path / "raw"
    extract_member(archive, MEMBER, dest)

    target = dest / MEMBER
    record_file = ExtractionRecord.path_for(target)

    assert not staging_path(target).exists()
    assert not staging_path(record_file).exists()


def test_sidecar_never_lands_partially(
    archive: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash DURING the sidecar write must leave no sidecar at all.

    write_atomic stages then replaces, so an interrupted write can only lose
    the staged file. The old behaviour -- write_text straight to the target --
    could leave truncated JSON under the real name.
    """
    dest = tmp_path / "raw"
    record_file = ExtractionRecord.path_for(dest / MEMBER)

    def _die_mid_write(target: Path, data: object, **kwargs: object) -> None:
        staging_path(target).write_text('{"archive": "partial')
        raise OSError("simulated crash during sidecar write")

    monkeypatch.setattr("spark_batch_pipeline.ingest.extract.write_atomic", _die_mid_write)

    with pytest.raises(OSError, match="simulated crash"):
        extract_member(archive, MEMBER, dest)

    assert (dest / MEMBER).read_bytes() == BODY, "phase 1 data should be intact"
    assert not record_file.exists(), "no sidecar may exist under the real name"


def test_recovery_after_partial_sidecar_write(
    archive: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Following the previous scenario, a clean re-run must complete the commit."""
    dest = tmp_path / "raw"

    def _die_mid_write(target: Path, data: object, **kwargs: object) -> None:
        staging_path(target).write_text('{"archive": "partial')
        raise OSError("simulated crash during sidecar write")

    monkeypatch.setattr("spark_batch_pipeline.ingest.extract.write_atomic", _die_mid_write)
    with pytest.raises(OSError):
        extract_member(archive, MEMBER, dest)

    monkeypatch.undo()
    record = extract_member(archive, MEMBER, dest)

    assert record.size_bytes == len(BODY)
    assert ExtractionRecord.path_for(dest / MEMBER).is_file()
