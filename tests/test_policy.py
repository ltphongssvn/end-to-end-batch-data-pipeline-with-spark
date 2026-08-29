# tests/test_policy.py
"""Zero-trust decompression policy.

The governing measurement, taken 2026-08-28: 10MB of zero bytes -- the most
compressible input that exists -- deflates to 1027.7x, just under DEFLATE's
theoretical ceiling of 1032. No legitimate single member can exceed that, so a
ratio threshold below 1032 rejects valid data by construction. Our own fixtures
reach 28x and 408x while being entirely benign.

That is why the ABSOLUTE byte caps are the control and the ratio is only a
structural-impossibility check. Size is what exhausts a disk.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from spark_batch_pipeline.ingest.policy import (
    ExtractionPolicy,
    PolicyViolationError,
    check_archive,
    check_member,
    enforce_while_writing,
    safe_member_name,
)

DEFLATE_CEILING = 1032.0


def _zip_with(tmp_path: Path, members: dict[str, bytes], name: str = "a.zip") -> Path:
    path = tmp_path / name
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
        for member, body in members.items():
            bundle.writestr(member, body)
    return path


def _info_for(body: bytes, name: str = "m.csv") -> zipfile.ZipInfo:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(name, body)
    with zipfile.ZipFile(buffer) as bundle:
        return bundle.infolist()[0]


# --- Zip Slip (CWE-22) ------------------------------------------------------


@pytest.mark.parametrize(
    "member",
    ["../../etc/passwd", "../escape.csv", "/absolute/path.csv", "a/../../b.csv"],
)
def test_escaping_member_names_are_refused(member: str) -> None:
    """Refused, not sanitized. Trimming to a basename neutralizes the traversal
    but lets two distinct members collapse onto one output name, so the archive
    still decides which write wins."""
    with pytest.raises(PolicyViolationError, match="escapes the destination"):
        safe_member_name(member)


@pytest.mark.parametrize("member", ["", "subdir/"])
def test_empty_and_directory_entries_are_refused(member: str) -> None:
    with pytest.raises(PolicyViolationError, match="empty or a directory"):
        safe_member_name(member)


def test_ordinary_names_pass_through(tmp_path: Path) -> None:
    assert safe_member_name("WDICSV.csv") == "WDICSV.csv"
    assert safe_member_name("nested/WDICSV.csv") == "WDICSV.csv"


# --- The ratio is a ceiling check, not a tuning knob ------------------------


def test_highly_compressible_data_is_not_a_bomb() -> None:
    """The false positive that makes people disable the scanner.

    Zero bytes are maximally compressible and still cannot pass 1032:1.
    """
    info = _info_for(b"\0" * (4 * 1024 * 1024))
    ratio = info.file_size / info.compress_size

    assert ratio > 500, "premise: this should be an extreme ratio"
    assert ratio < DEFLATE_CEILING, "DEFLATE cannot exceed its own ceiling"
    check_member(info, Path.cwd(), ExtractionPolicy())


def test_repetitive_csv_is_not_a_bomb() -> None:
    """Exactly the shape of this project's own test fixtures."""
    info = _info_for(b"Country,Code,1960\nAruba,ABW,1.5\n" * 60_000)

    assert info.file_size / info.compress_size > 100
    check_member(info, Path.cwd(), ExtractionPolicy())


def test_default_ratio_is_the_deflate_ceiling() -> None:
    """Guards the reasoning: a lower default silently reintroduces false
    positives on legitimate compressible input."""
    assert ExtractionPolicy().max_compression_ratio == DEFLATE_CEILING


# --- Absolute caps: the real control ----------------------------------------


def test_declared_size_over_the_cap_is_refused() -> None:
    info = _info_for(b"x" * 5000)
    with pytest.raises(PolicyViolationError, match="declares"):
        check_member(info, Path.cwd(), ExtractionPolicy(max_member_bytes=1024))


def test_streaming_abort_beats_a_lying_header() -> None:
    """THE guarantee. file_size is attacker-controlled, so an archive can claim
    1MB and stream 100GB. Only the counter catches that."""
    honest_looking = _info_for(b"x" * 100)
    policy = ExtractionPolicy(max_member_bytes=1024)

    check_member(honest_looking, Path.cwd(), policy)  # header passes

    with pytest.raises(PolicyViolationError, match="while extracting"):
        enforce_while_writing(5000, honest_looking.compress_size, honest_looking, policy)


def test_streaming_abort_reports_where_it_stopped() -> None:
    info = _info_for(b"x" * 100)
    with pytest.raises(PolicyViolationError, match="aborted after 2,048"):
        enforce_while_writing(2048, 100, info, ExtractionPolicy(max_member_bytes=1024))


def test_real_ratio_is_computed_from_written_bytes() -> None:
    """Measured output over compressed input, so a forged header cannot help."""
    info = _info_for(b"x" * 100)
    policy = ExtractionPolicy(max_compression_ratio=10.0)

    with pytest.raises(PolicyViolationError, match="real compression ratio"):
        enforce_while_writing(written=1000, compress_size=10, info=info, policy=policy)


# --- Archive-level limits ---------------------------------------------------


def test_too_many_members_refused(tmp_path: Path) -> None:
    """A bomb can be many small members rather than one large one."""
    archive = _zip_with(tmp_path, {f"m{i}.csv": b"data\n" for i in range(10)})

    with pytest.raises(PolicyViolationError, match="members, limit is"):
        check_archive(archive, ExtractionPolicy(max_members=5))


def test_declared_total_over_the_cap_refused(tmp_path: Path) -> None:
    archive = _zip_with(tmp_path, {"a.csv": b"x" * 5000, "b.csv": b"y" * 5000})

    with pytest.raises(PolicyViolationError, match="bytes uncompressed"):
        check_archive(archive, ExtractionPolicy(max_total_bytes=1024))


def test_normal_archive_passes_overlap_detection(tmp_path: Path) -> None:
    """Legitimate archives store each member's bytes once, so compressed sizes
    sum to no more than the file itself."""
    archive = _zip_with(tmp_path, {"a.csv": b"alpha\n" * 100, "b.csv": b"beta\n" * 100})

    check_archive(archive, ExtractionPolicy())


# --- Compression method allowlist -------------------------------------------


def test_disallowed_method_refused(tmp_path: Path) -> None:
    """Exotic codecs reach far higher ratios than deflate, so they are opt-in."""
    info = _info_for(b"data")
    policy = ExtractionPolicy(allowed_methods=frozenset({zipfile.ZIP_STORED}))

    with pytest.raises(PolicyViolationError, match="compression method"):
        check_member(info, Path.cwd(), policy)


def test_stored_and_deflated_are_allowed_by_default() -> None:
    allowed = ExtractionPolicy().allowed_methods
    assert zipfile.ZIP_STORED in allowed
    assert zipfile.ZIP_DEFLATED in allowed


# --- Disk space -------------------------------------------------------------


def test_insufficient_free_space_refused(tmp_path: Path) -> None:
    """Filling a volume takes down the host, not just this job."""
    info = _info_for(b"x" * 1000)
    absurd = ExtractionPolicy(free_space_headroom=1e12)

    with pytest.raises(PolicyViolationError, match="free"):
        check_member(info, tmp_path, absurd)


# --- The policy is data ------------------------------------------------------


def test_policy_is_frozen() -> None:
    """A limit mutated mid-run is not a limit.

    ValidationError specifically, not a bare Exception: a blind catch would pass
    on an AttributeError or a typo in the field name and assert nothing.
    """
    policy = ExtractionPolicy()

    with pytest.raises(ValidationError) as caught:
        policy.max_members = 1  # type: ignore[misc]

    assert caught.value.errors()[0]["type"] == "frozen_instance"


def test_policy_rejects_unknown_fields() -> None:
    """extra='forbid' turns a misspelled limit into a loud failure instead of a
    silently ignored setting that leaves the default in force."""
    with pytest.raises(ValidationError) as caught:
        ExtractionPolicy.model_validate({"max_membrs": 5})

    assert caught.value.errors()[0]["type"] == "extra_forbidden"
