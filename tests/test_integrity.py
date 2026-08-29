# tests/test_integrity.py
"""Cryptographic integrity of extracted members.

CRC-32 is a 32-bit checksum built to catch transmission noise. These tests
DEMONSTRATE its inadequacy rather than assert it: a real colliding pair is
found, one member of the pair is substituted for the other on disk, and the
CRC-only view reports the file as intact while the digest catches it.

HOW THE COLLISION IS FOUND, and why not by forgery. CRC-32 is linear over
GF(2), so a four-byte suffix can be computed to force any target checksum --
correct, and the wrong tool here: a test that ships a CRC forgery engine is a
liability, and an earlier attempt at it brute-forced a 3-byte suffix against a
32-bit target, which cannot work and burned four minutes proving it. A birthday
search over 2**16 short random strings finds a genuine collision in
milliseconds, because the space is only 32 bits wide. That the collision is
this cheap IS the argument.

The chain of custody is the second concern. The fetch manifest attests the
archive, this record attests a member, and archive_sha256 links them. Without
that link the two phases attest unrelated artifacts and "reprocess from raw"
cannot be traced back to a URL.
"""

from __future__ import annotations

import binascii
import hashlib
import os
import zipfile
from pathlib import Path

import pytest

from spark_batch_pipeline.ingest.extract import (
    ExtractionRecord,
    ExtractionState,
    digests_of,
    extract_member,
    inspect_extraction,
)

MEMBER = "WDICSV.csv"


def _find_crc_collision(width: int = 12, attempts: int = 1 << 18) -> tuple[bytes, bytes]:
    """Two distinct byte strings with an identical CRC-32.

    Birthday search: with a 32-bit output, roughly 2**16 samples give an even
    chance of a repeat, so 2**18 makes failure vanishingly unlikely while still
    finishing in milliseconds.
    """
    seen: dict[int, bytes] = {}
    for _ in range(attempts):
        candidate = os.urandom(width)
        crc = binascii.crc32(candidate)
        previous = seen.get(crc)
        if previous is not None and previous != candidate:
            return previous, candidate
        seen[crc] = candidate
    raise AssertionError(  # pragma: no cover - astronomically unlikely
        f"no CRC-32 collision in {attempts} samples"
    )


ORIGINAL, SUBSTITUTE = _find_crc_collision()


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    path = tmp_path / "WDI_CSV.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(MEMBER, ORIGINAL)
    return path


def test_crc_collisions_are_cheap_to_find() -> None:
    """The premise. If this ever fails, the argument below collapses."""
    assert ORIGINAL != SUBSTITUTE
    assert binascii.crc32(ORIGINAL) == binascii.crc32(SUBSTITUTE)
    assert hashlib.sha256(ORIGINAL).digest() != hashlib.sha256(SUBSTITUTE).digest()


def test_crc_preserving_substitution_is_detected(archive: Path, tmp_path: Path) -> None:
    """THE REASON SHA-256 IS HERE.

    The file on disk is replaced with different content of identical CRC. A
    CRC-only pipeline reports it as intact.
    """
    dest = tmp_path / "raw"
    extract_member(archive, MEMBER, dest)
    (dest / MEMBER).write_bytes(SUBSTITUTE)

    status = inspect_extraction(archive, MEMBER, dest)

    assert status.actual_crc32 == status.declared_crc32, "premise: CRC still agrees"
    assert status.state is ExtractionState.CORRUPT
    assert "SHA-256 does not" in status.detail


def test_substitution_is_repaired_on_the_next_run(archive: Path, tmp_path: Path) -> None:
    dest = tmp_path / "raw"
    extract_member(archive, MEMBER, dest)
    (dest / MEMBER).write_bytes(SUBSTITUTE)

    extract_member(archive, MEMBER, dest)

    assert (dest / MEMBER).read_bytes() == ORIGINAL
    assert inspect_extraction(archive, MEMBER, dest).state is ExtractionState.COMMITTED


def test_record_binds_member_to_its_archive(archive: Path, tmp_path: Path) -> None:
    """Closes the chain of custody between the two ingestion phases."""
    dest = tmp_path / "raw"
    record = extract_member(archive, MEMBER, dest)

    assert record.archive_sha256 == digests_of(archive)[1]
    assert record.sha256 == digests_of(dest / MEMBER)[1]
    assert record.sha256 != record.archive_sha256, "member is not the archive"


def test_digests_agree_with_the_obvious_implementation(tmp_path: Path) -> None:
    """digests_of reads via readinto over a reused buffer; confirm that
    optimisation did not change the answer."""
    blob = tmp_path / "blob.bin"
    payload = os.urandom(1 << 20)
    blob.write_bytes(payload)

    crc, sha = digests_of(blob)

    assert crc == binascii.crc32(payload)
    assert sha == hashlib.sha256(payload).hexdigest()


def test_empty_file_digests(tmp_path: Path) -> None:
    """readinto returns 0 immediately; the loop must terminate, not spin."""
    blob = tmp_path / "empty.bin"
    blob.write_bytes(b"")

    assert digests_of(blob) == (0, hashlib.sha256(b"").hexdigest())


def test_sidecar_digest_survives_the_json_round_trip(archive: Path, tmp_path: Path) -> None:
    """The model constrains length; this guards the value actually written."""
    dest = tmp_path / "raw"
    written = extract_member(archive, MEMBER, dest)

    reloaded = ExtractionRecord.model_validate_json(
        ExtractionRecord.path_for(dest / MEMBER).read_text()
    )
    assert reloaded.sha256 == written.sha256
    assert len(reloaded.sha256) == 64
    assert int(reloaded.sha256, 16) >= 0, "must be hex"
