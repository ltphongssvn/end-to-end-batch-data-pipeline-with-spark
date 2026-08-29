# tests/test_extract.py
"""Archive extraction tests.

Spark cannot read inside a zip, so this step is mandatory rather than an
optimisation, and the member is 198MB in production. Each test below encodes a
failure that costs real time or real correctness: re-inflating on every run,
accepting a corrupted member as truth, or publishing a partial file under the
real name.

Fixtures build small zips, so nothing here touches the real archive.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from spark_batch_pipeline.ingest.extract import (
    ExtractionRecord,
    crc32_of,
    extract_member,
)

BODY = b"Country Name,Country Code,1960\nAruba,ABW,1.5\n" * 40
MEMBER = "WDICSV.csv"


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    path = tmp_path / "WDI_CSV.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(MEMBER, BODY)
        bundle.writestr("WDICountry.csv", b"Country Code,Short Name\nABW,Aruba\n")
    return path


def test_extracts_bytes_verbatim(archive: Path, tmp_path: Path) -> None:
    """The raw layer is only replayable if what lands is what the source shipped."""
    dest = tmp_path / "raw"
    record = extract_member(archive, MEMBER, dest)

    target = dest / MEMBER
    assert target.read_bytes() == BODY
    assert record.size_bytes == len(BODY)
    assert record.member == MEMBER
    assert ExtractionRecord.path_for(target).exists()


def test_crc_matches_the_archive_declaration(archive: Path, tmp_path: Path) -> None:
    dest = tmp_path / "raw"
    record = extract_member(archive, MEMBER, dest)

    with zipfile.ZipFile(archive) as bundle:
        declared = bundle.getinfo(MEMBER).CRC & 0xFFFFFFFF

    assert record.crc32 == declared
    assert crc32_of(dest / MEMBER) == declared


def test_second_extraction_reuses_the_file(
    archive: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-inflating 198MB on every run is the cost this avoids.

    ZipFile.open is patched to explode after the first extraction, so a second
    inflation would fail loudly instead of merely being slow.
    """
    dest = tmp_path / "raw"
    first = extract_member(archive, MEMBER, dest)

    def _explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("re-inflated an already extracted member")

    monkeypatch.setattr(zipfile.ZipFile, "open", _explode)
    second = extract_member(archive, MEMBER, dest)

    assert second.crc32 == first.crc32


def test_edited_file_is_re_extracted(archive: Path, tmp_path: Path) -> None:
    """Length alone would not catch this.

    The file is overwritten with DIFFERENT CONTENT OF THE SAME LENGTH. A size
    comparison accepts it; a CRC comparison does not.
    """
    dest = tmp_path / "raw"
    extract_member(archive, MEMBER, dest)
    target = dest / MEMBER

    tampered = b"X" * len(BODY)
    target.write_bytes(tampered)
    assert target.stat().st_size == len(BODY), "test premise: same length"

    extract_member(archive, MEMBER, dest)

    assert target.read_bytes() == BODY


def test_force_re_extracts(archive: Path, tmp_path: Path) -> None:
    dest = tmp_path / "raw"
    extract_member(archive, MEMBER, dest)
    (dest / MEMBER).write_bytes(b"clobbered")

    extract_member(archive, MEMBER, dest, force=True)

    assert (dest / MEMBER).read_bytes() == BODY


def test_corrupt_member_never_reaches_the_real_name(
    archive: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Everything downstream treats the raw layer as truth, so a member whose
    CRC does not match must fail rather than be published."""
    dest = tmp_path / "raw"

    monkeypatch.setattr("spark_batch_pipeline.ingest.extract.crc32_of", lambda path: 0xDEADBEEF)

    with pytest.raises(ValueError, match="CRC mismatch"):
        extract_member(archive, MEMBER, dest)

    assert not (dest / MEMBER).exists(), "corrupt data was published"
    assert not (dest / f"{MEMBER}.part").exists(), "staged file was left behind"


def test_unknown_member_raises(archive: Path, tmp_path: Path) -> None:
    with pytest.raises(KeyError):
        extract_member(archive, "NOPE.csv", tmp_path / "raw")


def test_no_staged_file_survives_success(archive: Path, tmp_path: Path) -> None:
    dest = tmp_path / "raw"
    extract_member(archive, MEMBER, dest)

    assert not (dest / f"{MEMBER}.part").exists()


def test_record_round_trips_through_json(archive: Path, tmp_path: Path) -> None:
    """The sidecar is read back on the next run, so it must survive the trip."""
    dest = tmp_path / "raw"
    record = extract_member(archive, MEMBER, dest)

    reloaded = ExtractionRecord.model_validate_json(
        ExtractionRecord.path_for(dest / MEMBER).read_text()
    )
    assert reloaded == record
