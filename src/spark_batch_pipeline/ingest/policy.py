# src/spark_batch_pipeline/ingest/policy.py
"""Policy-controlled decompression for the ingestion trust boundary.

An archive fetched over the network is untrusted input, and ZIP is a 35-year-old
format designed before adversarial inputs were a consideration. Uncontrolled
decompression is CWE-409; CVE-2026-22870 hit GuardDog's safe_extract in January
2026 for exactly this, rated HIGH.

WHY THE DECLARED SIZE IS NOT THE CHECK
The obvious guard is `info.file_size <= limit`. It is necessary and completely
insufficient: file_size is a field in the archive, so it is attacker-controlled.
An archive can declare 1 MB and stream 100 GB. Tools that trust that field are
the ones that get fooled.

The authority is therefore the BYTE COUNTER during streaming extraction, which
aborts mid-write the moment a limit is crossed. The declared size is used only
as a cheap early rejection, so an obviously hostile archive costs nothing --
never as the guarantee.

WHAT IS ENFORCED
  member count       a bomb can be many small members rather than one large one
  declared size      cheap early reject; advisory only
  actual bytes       authoritative, counted while writing
  compression ratio  computed from bytes ACTUALLY written over the compressed
                     size, so it too cannot be forged by the header
  compression method allowlist; exotic codecs reach far higher ratios
  member name        rejected, not sanitized, if it escapes its directory
  free disk space    refuse rather than fill the volume and take the host down

WHY REJECT RATHER THAN SANITIZE A BAD NAME: silently reducing "../../etc/passwd"
to "passwd" neutralizes the traversal but can collapse two distinct members onto
one output name, so the archive still decides what the last write wins. A name
that tries to escape is evidence of intent and should stop the ingest.

DEFAULTS are sized against the MEASURED archive, not a guess. Observed
2026-08-28 for WDI_CSV.zip:

    member                   uncompressed     compressed   ratio  method
    WDICSV.csv                198,481,686    198,511,971    1.00       8
    WDIfootnote.csv            76,824,428     76,836,153    1.00       8
    WDISeries.csv               5,961,768      5,962,678    1.00       8
    WDIcountry-series.csv       1,362,558      1,362,768    1.00       8
    WDICountry.csv                156,476        156,501    1.00       8
    WDIseries-time.csv             14,388         14,393    1.00       8
    TOTAL                     282,801,304    282,844,464    1.00
    6 members, all ZIP_DEFLATED

Every member compresses to slightly MORE than its input: deflate is applied but
achieves nothing, so the payload is already compressed or effectively stored.

WHY THE RATIO LIMIT IS NOT THE PRIMARY CONTROL: the obvious move is a tight
ratio cap, and it is wrong. DEFLATE cannot exceed 1032:1 for a single member,
so any threshold below that rejects data which is merely very compressible
rather than hostile. This project's own test fixtures reach 31x and 341x while
being completely benign. A control that blocks valid input is worse than no
control, because it gets disabled.

Bombs beat 1032 in only two ways, and neither is a ratio problem:
  RECURSION    nested archives, each layer multiplying by up to 1032. We never
               unpack recursively, so 42.zip is inert here.
  OVERLAPPING  many central-directory entries pointing at one kernel of
               compressed data, which is how a flat bomb reaches millions to
               one. check_archive detects this by comparing the sum of the
               members' compressed sizes against the archive's actual size.

The real limits are the ABSOLUTE byte caps, enforced by a counter during
streaming extraction. Size is what exhausts a disk; ratio is only a hint.
"""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, PositiveFloat, PositiveInt

# ZIP_STORED and ZIP_DEFLATED cover every member the World Bank ships. BZIP2 and
# LZMA are legitimate but reach far higher ratios, so they are opt-in.
_DEFAULT_METHODS: frozenset[int] = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})

_GIB = 1024**3


class PolicyViolationError(Exception):
    """An archive or member was refused before or during extraction.

    A distinct type, not ValueError: a policy refusal is a security decision a
    caller may want to handle, alert on, or quarantine differently from a
    corrupt download.
    """


class ExtractionPolicy(BaseModel):
    """Limits applied to an untrusted archive."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Measured largest member: 198MB. 4 GiB is ~20x that, so years of growth
    # pass while a runaway inflation is stopped well before it fills a volume.
    max_member_bytes: PositiveInt = 4 * _GIB
    max_total_bytes: PositiveInt = 8 * _GIB
    # Measured: 6 members. 64 leaves generous room for new tables without
    # admitting an archive whose bomb is many small entries rather than one.
    max_members: PositiveInt = 64

    # 1032 is DEFLATE's THEORETICAL CEILING, not a tuning choice. A single
    # deflate member cannot exceed it, so any threshold below 1032 rejects data
    # that is merely very compressible -- a false positive by construction. Our
    # own fixtures proved it: repetitive CSV reaches 31x and 341x while being
    # entirely legitimate, and the field reports the same pain with thresholds
    # of 10. A scanner that blocks valid input gets switched off.
    #
    # Bombs beat 1032 only by RECURSION or by OVERLAPPING central-directory
    # entries, and both are caught elsewhere: overlap by check_archive, size by
    # the absolute caps, runaway inflation by the streaming byte counter. The
    # ratio is therefore a structural impossibility check, not the real limit.
    max_compression_ratio: PositiveFloat = 1032.0

    allowed_methods: frozenset[int] = Field(default=_DEFAULT_METHODS)

    # Refuse when the volume would be left with less than this multiple of the
    # member's declared size. Filling a disk takes down the host, not just this job.
    free_space_headroom: PositiveFloat = 1.5


def _reject(reason: str) -> None:
    raise PolicyViolationError(reason)


def safe_member_name(member: str) -> str:
    """Return the basename of `member`, or refuse if the name tries to escape.

    Zip Slip (CWE-22): a member named "../../etc/passwd" writes outside the
    destination. Refusing rather than silently trimming the path keeps two
    members from collapsing onto one output name.
    """
    if not member or member.endswith("/"):
        _reject(f"member name is empty or a directory entry: {member!r}")
    candidate = Path(member)
    if candidate.is_absolute() or ".." in candidate.parts:
        _reject(f"member name escapes the destination directory: {member!r}")
    return candidate.name


def resolve_unique_member(bundle: zipfile.ZipFile, member: str) -> zipfile.ZipInfo:
    """Resolve `member` to EXACTLY ONE entry, or refuse.

    ZIP permits duplicate filenames, and such archives exist in the wild.
    CPython keeps only the LAST entry for a given name in its internal name
    index, so a name-based lookup silently binds to whichever duplicate came
    last -- and can even fail outright with "Overlapped entries: possible zip
    bomb" while opening the same file by its ZipInfo succeeds
    (python/cpython#117779).

    That destroys provenance. The sidecar attests a CRC for "the member called
    X", but with duplicates there is no such thing as "the" member: another
    tool reading the same archive may legitimately resolve X to different
    bytes. A checksum that identifies the wrong entry is worse than none,
    because it asserts a guarantee it does not hold.

    Callers must pass the returned ZipInfo to open(), never the name, so the
    entry that was inspected is provably the entry that gets read.
    """
    matches = [info for info in bundle.infolist() if info.filename == member]

    if not matches:
        # KeyError preserves zipfile's own contract for an unknown member, so
        # callers distinguishing "absent" from "refused" keep working.
        raise KeyError(member)

    if len(matches) > 1:
        _reject(
            f"archive contains {len(matches)} entries named {member!r}; "
            "provenance is ambiguous because a name cannot identify which "
            "bytes were verified"
        )

    return matches[0]


def check_archive(archive: Path, policy: ExtractionPolicy) -> None:
    """Validate archive-level limits before opening any member."""
    with zipfile.ZipFile(archive) as bundle:
        infos = bundle.infolist()

    if len(infos) > policy.max_members:
        _reject(f"archive holds {len(infos)} members, limit is {policy.max_members}")

    declared_total = sum(info.file_size for info in infos)
    if declared_total > policy.max_total_bytes:
        _reject(
            f"archive declares {declared_total:,} bytes uncompressed, limit is "
            f"{policy.max_total_bytes:,}"
        )

    # FLAT BOMB DETECTION. A non-recursive bomb makes many central-directory
    # entries point at one shared kernel of compressed data, so the archive
    # claims far more compressed content than the file physically holds. That
    # overlap is how a bomb exceeds DEFLATE's 1032:1 ceiling without nesting.
    # Legitimate archives store each member's bytes once, so their compressed
    # sizes sum to at most the file size plus header overhead.
    compressed_total = sum(info.compress_size for info in infos)
    archive_bytes = archive.stat().st_size
    if compressed_total > archive_bytes:
        _reject(
            f"archive members claim {compressed_total:,} compressed bytes but "
            f"the file is only {archive_bytes:,}; entries overlap, which is the "
            "flat zip bomb construction"
        )


def check_member(info: zipfile.ZipInfo, dest_dir: Path, policy: ExtractionPolicy) -> None:
    """Validate one member's declared metadata before inflating it.

    Every check here is ADVISORY: the fields come from the archive. Their value
    is rejecting an obviously hostile input cheaply. The binding limit is
    enforced by the byte counter during extraction.
    """
    safe_member_name(info.filename)

    if info.compress_type not in policy.allowed_methods:
        _reject(
            f"member {info.filename!r} uses compression method "
            f"{info.compress_type}, which is not allowed"
        )

    if info.file_size > policy.max_member_bytes:
        _reject(
            f"member {info.filename!r} declares {info.file_size:,} bytes, limit "
            f"is {policy.max_member_bytes:,}"
        )

    if info.compress_size > 0:
        declared_ratio = info.file_size / info.compress_size
        if declared_ratio > policy.max_compression_ratio:
            _reject(
                f"member {info.filename!r} declares a compression ratio of "
                f"{declared_ratio:.1f}x, limit is {policy.max_compression_ratio:g}x"
            )

    required = int(info.file_size * policy.free_space_headroom)
    free = shutil.disk_usage(dest_dir).free
    if free < required:
        _reject(
            f"extracting {info.filename!r} needs about {required:,} bytes free "
            f"with headroom, only {free:,} available"
        )


def enforce_while_writing(
    written: int, compress_size: int, info: zipfile.ZipInfo, policy: ExtractionPolicy
) -> None:
    """Abort mid-write once real output crosses a limit.

    THIS is the guarantee. Both quantities are measured, not declared: `written`
    is what the decompressor actually produced, so an archive that lies in its
    header is caught here rather than after it has filled the disk.
    """
    if written > policy.max_member_bytes:
        _reject(
            f"member {info.filename!r} exceeded {policy.max_member_bytes:,} bytes "
            f"while extracting; aborted after {written:,}"
        )

    if compress_size > 0:
        ratio = written / compress_size
        if ratio > policy.max_compression_ratio:
            _reject(
                f"member {info.filename!r} reached a real compression ratio of "
                f"{ratio:.1f}x, limit is {policy.max_compression_ratio:g}x; "
                f"aborted after {written:,} bytes"
            )
