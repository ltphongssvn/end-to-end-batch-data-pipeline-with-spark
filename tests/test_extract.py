# tests/test_extract.py
"""Archive extraction.

Spark cannot read inside a zip, so this step is mandatory rather than an
optimisation, and the member is 198MB in production. Each test encodes a failure
that costs real time or real correctness: re-inflating on every run, accepting a
corrupted member as truth, or publishing a partial file under the real name.

FAULT INJECTION IS DATA-LEVEL, NOT IMPLEMENTATION-LEVEL. An earlier version
monkeypatched crc32_of to force a mismatch. That patch broke the moment the
write loop was refactored to digest bytes inline -- the function was no longer
on the path, so the test silently stopped testing anything and reported DID NOT
RAISE. Patching internals couples a test to implementation details and makes it
brittle across exactly the refactors it should survive. Corrupting the archive
instead exercises whatever the real path happens to be.

Fixtures build small zips, so nothing here touches the real archive.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from spark_batch_pipeline.atomicio import staging_path
from spark_batch_pipeline.ingest.extract import (
    ExtractionRecord,
    crc32_of,
    digests_of,
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


def test_record_carries_both_digests(archive: Path, tmp_path: Path) -> None:
    """SHA-256 is the root of trust; CRC is only a transport check.

    archive_sha256 closes the chain of custody: without it the fetch manifest
    and this record attest unrelated artifacts.
    """
    dest = tmp_path / "raw"
    record = extract_member(archive, MEMBER, dest)

    expected_crc, expected_sha = digests_of(dest / MEMBER)
    assert record.sha256 == expected_sha
    assert record.crc32 == expected_crc
    assert len(record.archive_sha256) == 64
    assert record.archive_sha256 == digests_of(archive)[1]


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

    ZipFile.open is patched to explode AFTER the first extraction, so a second
    inflation fails loudly rather than merely being slow. Patching here is about
    proving a call does not happen, which data alone cannot express.
    """
    dest = tmp_path / "raw"
    first = extract_member(archive, MEMBER, dest)

    def _explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("re-inflated an already extracted member")

    monkeypatch.setattr(zipfile.ZipFile, "open", _explode)
    second = extract_member(archive, MEMBER, dest)

    assert second.sha256 == first.sha256


def test_edited_file_is_re_extracted(archive: Path, tmp_path: Path) -> None:
    """Length alone would not catch this.

    The file is overwritten with DIFFERENT CONTENT OF THE SAME LENGTH. A size
    comparison accepts it; a checksum does not.
    """
    dest = tmp_path / "raw"
    extract_member(archive, MEMBER, dest)
    target = dest / MEMBER

    target.write_bytes(b"X" * len(BODY))
    assert target.stat().st_size == len(BODY), "test premise: same length"

    extract_member(archive, MEMBER, dest)

    assert target.read_bytes() == BODY


def test_force_re_extracts(archive: Path, tmp_path: Path) -> None:
    dest = tmp_path / "raw"
    extract_member(archive, MEMBER, dest)
    (dest / MEMBER).write_bytes(b"clobbered")

    extract_member(archive, MEMBER, dest, force=True)

    assert (dest / MEMBER).read_bytes() == BODY


def test_corrupt_member_never_reaches_the_real_name(tmp_path: Path) -> None:
    """A member whose bytes do not match its declared CRC must not be published.

    The corruption is in the ARCHIVE, not in a patched function, so this holds
    whichever layer catches it: zipfile validates CRC while reading and raises
    BadZipFile, and the explicit check in extract_member raises ValueError.
    Asserting the outcome rather than the mechanism keeps the test meaningful
    across refactors of the read path.
    """
    path = tmp_path / "WDI_CSV.zip"
    # STORED so the payload appears verbatim in the file and can be corrupted.
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as bundle:
        bundle.writestr(MEMBER, BODY)

    raw = bytearray(path.read_bytes())
    offset = raw.find(BODY)
    assert offset != -1, "test premise: stored payload is findable"
    raw[offset] ^= 0xFF
    path.write_bytes(bytes(raw))

    dest = tmp_path / "raw"
    with pytest.raises((ValueError, zipfile.BadZipFile)):
        extract_member(path, MEMBER, dest)

    assert not (dest / MEMBER).exists(), "corrupt data was published"
    # Staging files specifically. The lock file beside the target is NOT
    # garbage: atomicio leaves it deliberately, because unlinking it races with
    # a process that has already opened it and would let two holders coexist on
    # different inodes.
    assert not list(dest.glob("*.part")), "staging garbage was left behind"


def test_unknown_member_raises(archive: Path, tmp_path: Path) -> None:
    with pytest.raises(KeyError):
        extract_member(archive, "NOPE.csv", tmp_path / "raw")


def test_no_staged_file_survives_success(archive: Path, tmp_path: Path) -> None:
    dest = tmp_path / "raw"
    extract_member(archive, MEMBER, dest)

    assert not staging_path(dest / MEMBER).exists()
    assert not list(dest.glob("*.part"))


def test_record_round_trips_through_json(archive: Path, tmp_path: Path) -> None:
    """The sidecar is read back on the next run, so it must survive the trip."""
    dest = tmp_path / "raw"
    record = extract_member(archive, MEMBER, dest)

    reloaded = ExtractionRecord.model_validate_json(
        ExtractionRecord.path_for(dest / MEMBER).read_text()
    )
    assert reloaded == record
