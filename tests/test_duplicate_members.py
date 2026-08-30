# tests/test_duplicate_members.py
"""Duplicate archive member names.

ZIP permits two entries with the same filename, and such archives exist in the
wild. CPython keeps only the LAST entry in its internal name index, so
getinfo(name) silently binds to one of several -- and can fail outright with
"Overlapped entries: possible zip bomb" while opening the same file by its
ZipInfo succeeds (python/cpython#117779).

That destroys provenance. The sidecar attests a CRC for "the member called X",
but with duplicates there is no "the" member: another reader may resolve X to
different bytes. A checksum identifying the wrong entry is worse than none,
because it asserts a guarantee it does not hold.

WARNINGS ARE ASSERTED, NOT SUPPRESSED. Writing a duplicate name makes zipfile
emit a UserWarning, and the fixture below expects it via pytest.warns rather
than silencing it with warnings.catch_warnings. Two reasons: a manual
catch_warnings block outside pytest.warns leaves pytest unable to capture the
warning and mutates global filter state, and more importantly a suppression
hides the day zipfile STOPS warning -- which would mean the fixture is no
longer building the archive this whole file is about.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from spark_batch_pipeline.ingest.extract import (
    extract_member,
    inspect_extraction,
    resolve_unique_member,
)
from spark_batch_pipeline.ingest.policy import PolicyViolationError

MEMBER = "WDICSV.csv"
FIRST = b"FIRST entry payload\n" * 10
SECOND = b"SECOND entry payload\n" * 10


@pytest.fixture
def duplicate_archive(tmp_path: Path) -> Path:
    """An archive with two entries sharing one name.

    pytest.warns doubles as an assertion that zipfile still objects to this,
    so the fixture cannot silently stop producing a duplicate.
    """
    path = tmp_path / "dup.zip"
    with (
        pytest.warns(UserWarning, match="Duplicate name"),
        zipfile.ZipFile(path, "w") as bundle,
    ):
        bundle.writestr(MEMBER, FIRST)
        bundle.writestr(MEMBER, SECOND)
    return path


@pytest.fixture
def unique_archive(tmp_path: Path) -> Path:
    path = tmp_path / "ok.zip"
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr(MEMBER, FIRST)
    return path


def test_the_premise_getinfo_binds_to_the_last_entry(duplicate_archive: Path) -> None:
    """Documents the CPython behavior this guard exists for.

    If a future CPython changes which duplicate wins, this test says so, and the
    reasoning in resolve_unique_member can be revisited deliberately rather than
    discovered through a corrupted sidecar.
    """
    with zipfile.ZipFile(duplicate_archive) as bundle:
        named = [i for i in bundle.infolist() if i.filename == MEMBER]
        assert len(named) == 2

        assert bundle.read(bundle.getinfo(MEMBER)) == SECOND, (
            "name lookup no longer binds to the last entry"
        )


def test_duplicate_members_are_refused(duplicate_archive: Path) -> None:
    with (
        pytest.raises(PolicyViolationError, match="provenance is ambiguous"),
        zipfile.ZipFile(duplicate_archive) as bundle,
    ):
        resolve_unique_member(bundle, MEMBER)


def test_extraction_refuses_a_duplicate_member(duplicate_archive: Path, tmp_path: Path) -> None:
    """Refused rather than silently extracting whichever entry happened to win."""
    dest = tmp_path / "raw"

    with pytest.raises(PolicyViolationError, match="2 entries named"):
        extract_member(duplicate_archive, MEMBER, dest)

    assert not (dest / MEMBER).exists(), "ambiguous bytes must not be published"


def test_inspection_also_refuses(duplicate_archive: Path, tmp_path: Path) -> None:
    """A state query must not report a clean state for an archive that cannot be
    extracted, or a supervising process sees ABSENT and never learns why the
    work keeps failing."""
    with pytest.raises(PolicyViolationError, match="provenance is ambiguous"):
        inspect_extraction(duplicate_archive, MEMBER, tmp_path / "raw")


def test_unique_member_resolves(unique_archive: Path) -> None:
    with zipfile.ZipFile(unique_archive) as bundle:
        info = resolve_unique_member(bundle, MEMBER)

    assert info.filename == MEMBER
    assert info.file_size == len(FIRST)


def test_absent_member_raises_key_error(unique_archive: Path) -> None:
    """KeyError preserves zipfile's own contract, so callers distinguishing
    'absent' from 'refused' keep working."""
    with zipfile.ZipFile(unique_archive) as bundle, pytest.raises(KeyError):
        resolve_unique_member(bundle, "NOPE.csv")


def test_extraction_reads_the_resolved_entry(unique_archive: Path, tmp_path: Path) -> None:
    """open(info), not open(name): the entry inspected is the entry read."""
    dest = tmp_path / "raw"

    extract_member(unique_archive, MEMBER, dest)

    assert (dest / MEMBER).read_bytes() == FIRST
