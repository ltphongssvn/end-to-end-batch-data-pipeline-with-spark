# tests/test_extract_states.py
"""Every extraction state, asserted individually.

These are the tests the state machine made possible. Previously the same
conditions existed only inside one compound boolean, so a case could only be
probed by running a 198MB extraction and inferring what happened. Now the state
is resolved without doing any work, and each transition is checked on its own.

The pairing matters as much as the states: for each one, assert both what
inspect_extraction reports AND what extract_member then does about it.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from spark_batch_pipeline.atomicio import staging_path
from spark_batch_pipeline.ingest.extract import (
    ExtractionRecord,
    ExtractionState,
    extract_member,
    inspect_extraction,
)

BODY = b"Country Name,Country Code,1960\nAruba,ABW,1.5\n" * 40
OTHER_BODY = b"Country Name,Country Code,1960\nBrazil,BRA,9.9\n" * 40
MEMBER = "WDICSV.csv"


def _archive(path: Path, body: bytes = BODY) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(MEMBER, body)
    return path


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    return _archive(tmp_path / "WDI_CSV.zip")


@pytest.fixture
def dest(tmp_path: Path) -> Path:
    path = tmp_path / "raw"
    path.mkdir()
    return path


def test_absent_before_anything_happens(archive: Path, dest: Path) -> None:
    status = inspect_extraction(archive, MEMBER, dest)

    assert status.state is ExtractionState.ABSENT
    assert status.needs_work
    assert status.record is None
    assert status.declared_crc32 != 0


def test_committed_after_a_successful_run(archive: Path, dest: Path) -> None:
    extract_member(archive, MEMBER, dest)

    status = inspect_extraction(archive, MEMBER, dest)

    assert status.state is ExtractionState.COMMITTED
    assert not status.needs_work
    assert status.actual_crc32 == status.declared_crc32
    assert status.record is not None


def test_staged_when_a_run_died_mid_write(archive: Path, dest: Path) -> None:
    """In-flight is neither absent nor complete. Conflating the three is the
    classic idempotency bug."""
    staging_path(dest / MEMBER).write_bytes(BODY[:100])

    status = inspect_extraction(archive, MEMBER, dest)

    assert status.state is ExtractionState.STAGED
    assert status.needs_work


def test_staged_is_resolved_by_re_extracting(archive: Path, dest: Path) -> None:
    """A zip member cannot be inflated from an arbitrary offset, so a partial
    holds no reusable value and is overwritten rather than resumed."""
    staged = staging_path(dest / MEMBER)
    staged.write_bytes(b"garbage from a dead run")

    extract_member(archive, MEMBER, dest)

    assert (dest / MEMBER).read_bytes() == BODY
    assert not staged.exists()
    assert inspect_extraction(archive, MEMBER, dest).state is ExtractionState.COMMITTED


def test_orphaned_when_the_sidecar_is_missing(archive: Path, dest: Path) -> None:
    """The phase-1 crash window: complete bytes that nothing references."""
    extract_member(archive, MEMBER, dest)
    ExtractionRecord.path_for(dest / MEMBER).unlink()

    status = inspect_extraction(archive, MEMBER, dest)

    assert status.state is ExtractionState.ORPHANED
    assert status.needs_work


def test_orphaned_when_the_sidecar_is_unparseable(archive: Path, dest: Path) -> None:
    extract_member(archive, MEMBER, dest)
    ExtractionRecord.path_for(dest / MEMBER).write_text('{"archive": ')

    assert inspect_extraction(archive, MEMBER, dest).state is ExtractionState.ORPHANED


def test_stale_when_the_source_archive_changed(tmp_path: Path, dest: Path) -> None:
    """A sidecar surviving a source change must not certify the new content.

    This is the mismatched-state window the two-phase protocol is accused of
    leaving open. It resolves to STALE and is re-extracted, rather than being
    silently trusted.
    """
    archive = _archive(tmp_path / "v1.zip", BODY)
    extract_member(archive, MEMBER, dest)

    changed = _archive(tmp_path / "v2.zip", OTHER_BODY)
    status = inspect_extraction(changed, MEMBER, dest)

    assert status.state is ExtractionState.STALE
    assert status.record is not None
    assert status.record.crc32 != status.declared_crc32


def test_stale_is_resolved_by_re_extracting(tmp_path: Path, dest: Path) -> None:
    archive = _archive(tmp_path / "v1.zip", BODY)
    extract_member(archive, MEMBER, dest)

    changed = _archive(tmp_path / "v2.zip", OTHER_BODY)
    extract_member(changed, MEMBER, dest)

    assert (dest / MEMBER).read_bytes() == OTHER_BODY
    assert inspect_extraction(changed, MEMBER, dest).state is ExtractionState.COMMITTED


def test_corrupt_when_the_file_was_edited_in_place(archive: Path, dest: Path) -> None:
    """Same length, different content. A size check accepts this; a CRC does not."""
    extract_member(archive, MEMBER, dest)
    target = dest / MEMBER
    target.write_bytes(b"X" * len(BODY))

    status = inspect_extraction(archive, MEMBER, dest)

    assert status.state is ExtractionState.CORRUPT
    assert status.actual_crc32 != status.declared_crc32
    assert status.record is not None, "the sidecar itself is still valid"


def test_corrupt_is_resolved_by_re_extracting(archive: Path, dest: Path) -> None:
    extract_member(archive, MEMBER, dest)
    (dest / MEMBER).write_bytes(b"X" * len(BODY))

    extract_member(archive, MEMBER, dest)

    assert (dest / MEMBER).read_bytes() == BODY


def test_only_committed_skips_work(archive: Path, dest: Path) -> None:
    """needs_work is the whole decision, so it must be exhaustive."""
    working = {s for s in ExtractionState if s.needs_work}
    assert working == set(ExtractionState) - {ExtractionState.COMMITTED}


def test_status_serializes_for_a_supervising_process(archive: Path, dest: Path) -> None:
    """State must be reportable without running the extraction, so a caller can
    decide, gate, or alert on it."""
    extract_member(archive, MEMBER, dest)

    payload = inspect_extraction(archive, MEMBER, dest).model_dump(mode="json")

    assert payload["state"] == "committed"
    assert isinstance(payload["declared_crc32"], int)
    assert payload["member"] == MEMBER


def test_inspection_does_not_extract(archive: Path, dest: Path) -> None:
    """The point of separating decision from action: inspecting must be cheap."""
    inspect_extraction(archive, MEMBER, dest)

    assert not (dest / MEMBER).exists()
    assert not staging_path(dest / MEMBER).exists()
