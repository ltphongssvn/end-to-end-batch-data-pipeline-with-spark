# src/spark_batch_pipeline/ingest/extract.py
"""Extract archive members into the raw layer, as an explicit state machine.

WHY THIS IS NOT OPTIONAL: Spark reads gzip and bzip2 natively but NOT zip.
WDI_CSV.zip must be expanded before any DataFrame can touch it, and the member
is 198MB, so re-running must not repeat the work.

INTEGRITY: SHA-256 IS THE ROOT OF TRUST, CRC-32 IS NOT
CRC-32 is a 32-bit checksum designed to catch transmission noise. Collisions are
trivial to construct, so it cannot attest that content is what the source
published: bytes substituted after extraction can preserve the CRC exactly. It
is kept because ZIP supplies it for free and it fails fast on a damaged file --
a transport check, not a guarantee.

The chain of custody runs: URL -> archive SHA-256 (fetch manifest) -> member
SHA-256 + CRC (this record), with archive_sha256 copied forward so the member is
provably tied to the archive it came from. Without that link the two phases
attest unrelated things and "reprocess from raw" cannot be traced.

Upstream signing would be the next tier, and it does not exist: the World Bank
publishes no signatures for WDI, so there is no provenance to verify against.
Trust is therefore anchored to the first observed digest, recorded in the
manifest, and any later change is detectable even though its legitimacy cannot
be judged from the artifact alone.

WHY A STATE MACHINE RATHER THAN NESTED CONDITIONS
The states below always existed but were encoded implicitly in file existence
and one compound boolean. Implicit states cannot be inspected without performing
the work, asserted individually, or reported to a supervising process.
inspect_extraction() resolves the state WITHOUT extracting anything.

    ABSENT     no data file. Nothing has happened yet.
    STAGED     staging files survive from a run that died mid-write. Garbage to
               clean, not a partial to resume: a zip member cannot be inflated
               from an arbitrary offset.
    ORPHANED   data present, sidecar missing or unparseable. The phase-1 crash
               window: complete bytes that nothing references. The SAFE
               direction of failure, simply redone.
    STALE      sidecar readable but its CRC disagrees with what the archive now
               declares. The source changed under us.
    CORRUPT    the file on disk does not match what both the archive and the
               sidecar say it should be.
    COMMITTED  archive, sidecar, and file agree on CRC and SHA-256. The only
               state that skips work.

CONCURRENCY: idempotent-under-sequential-execution and safe-under-concurrency
are different properties. Two agents extracting the same member would otherwise
open one fixed staging name, truncate it, and race on the rename. The whole
check-and-commit sequence runs under exclusive_lock, and the staging name is
unique per run so a dead run's leftovers cannot be mistaken for the current one.

The state is resolved TWICE on purpose: once outside the lock for a cheap
answer, once inside before acting. The first is advisory and may be stale by the
time it returns; only the second is a decision.

COMMIT PROTOCOL, both phases symmetrical:
    stage data     -> verify -> publish data     (atomic + durable)
    render sidecar ->           publish sidecar  (atomic + durable)
Data is published first, so a crash between phases yields ORPHANED, never a
sidecar describing data that was never written. Orphans are recoverable;
dangling pointers are not.

ZERO-TRUST DECOMPRESSION: an archive fetched over the network is untrusted
input, so inflation is policy-controlled (policy.py). `info.file_size` is a
field IN the archive and therefore attacker-controlled: checking it is a cheap
early reject, never the guarantee. The binding limit is a byte counter that
aborts mid-write.

CRC comes from binascii, not zipfile. zipfile.crc32 exists at runtime only as a
private re-export of binascii.crc32; depending on it is depending on an
implementation detail, which is what mypy flags.

STAYS RAW: bytes are written exactly as stored. No parsing, re-encoding, or
newline translation. The raw layer is only replayable if what lands is what the
source shipped.
"""

from __future__ import annotations

import binascii
import hashlib
import zipfile
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from spark_batch_pipeline.atomicio import (
    STAGING_SUFFIX,
    exclusive_lock,
    new_staging_path,
    publish,
    write_atomic,
)
from spark_batch_pipeline.ingest.fetch import IngestManifest
from spark_batch_pipeline.ingest.policy import (
    ExtractionPolicy,
    check_archive,
    check_member,
    enforce_while_writing,
    resolve_unique_member,
    safe_member_name,
)
from spark_batch_pipeline.valuetypes import (
    ByteCount,
    Crc32,
    MemberName,
    PathString,
    Sha256,
    UtcTimestamp,
)

# VERSIONED CONTRACT. A sidecar outlives the code that wrote it -- it is read on
# every later run, possibly by a newer version of this module. Without a version
# a future reader cannot tell whether a missing field means "v1, which never had
# it" or "v2, corrupted". Kubernetes carries apiVersion in every manifest for
# the same reason: configuration survives the binary that produced it.
#
# The Literal is the dispatch point. A reader pinned to v1 fails loudly on a v2
# sidecar instead of silently misreading it, and when v2 arrives the two models
# become a discriminated union keyed on this field.
#
# DEFAULTED, WHICH IS THE NON-BREAKING FORM. Adding an optional field with a
# default is the standard backward-compatible change; Avro and Protobuf rely on
# exactly this, populating the default when deserializing older records.
# Sidecars written before this field existed have precisely the v1 field set, so
# reading them as v1 is accurate rather than a fudge. Requiring it would make
# every existing sidecar unparseable -- safe, because the orphan model redoes the
# step, but it would re-download 283MB and re-extract 198MB to recover a version
# string describing a shape that already matches.
#
# WHEN v2 ARRIVES: add a new literal, never repurpose this one. Changing the
# meaning of an existing default silently rewrites the interpretation of every
# historical record.
type ExtractRecordVersion = Literal["extract-record/v1"]
EXTRACT_RECORD_VERSION: Final[ExtractRecordVersion] = "extract-record/v1"

_COPY_BYTES = 8 * 1024 * 1024
_CRC_MASK = 0xFFFFFFFF


class ExtractionState(StrEnum):
    """Every state a member can occupy in the raw layer."""

    ABSENT = "absent"
    STAGED = "staged"
    ORPHANED = "orphaned"
    STALE = "stale"
    CORRUPT = "corrupt"
    COMMITTED = "committed"

    @property
    def needs_work(self) -> bool:
        """COMMITTED is the only state that skips extraction."""
        return self is not ExtractionState.COMMITTED


class ExtractionRecord(BaseModel):
    """Sidecar attesting which bytes were extracted, from which archive."""

    # strict: an attestation must not be built from coerced input. Lax mode
    # accepts 1.0 for a byte count or True for a CRC, letting malformed data
    # become apparently valid data at the one boundary where that matters.
    # Pydantic is looser from JSON by design, so extracted_at still parses from
    # an ISO string and the sidecar round trip is unaffected.
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    # First field so it is the first key a human sees in the JSON.
    schema_version: ExtractRecordVersion = EXTRACT_RECORD_VERSION

    archive: PathString
    member: MemberName
    size_bytes: ByteCount

    # THE ROOT OF TRUST for these bytes. Sha256 requires 64 lowercase HEX
    # digits; the previous min_length/max_length pair accepted ANY 64
    # characters, so a sidecar corrupted to the right length passed as a valid
    # attestation.
    sha256: Sha256

    # BINDS THIS RECORD TO ITS ARCHIVE, closing the chain of custody between the
    # fetch manifest and this extraction. Without it the two phases attest
    # unrelated artifacts.
    archive_sha256: Sha256

    # Transport-corruption check only. Cheap, native to ZIP, fails fast.
    crc32: Crc32

    # Timezone-aware: a naive timestamp cannot order two records written on
    # machines in different zones.
    extracted_at: UtcTimestamp

    @staticmethod
    def path_for(target: Path) -> Path:
        return target.with_name(target.name + ".extract.json")


class ExtractionStatus(BaseModel):
    """Resolved state of one member, computed without extracting anything."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: ExtractionState
    member: MemberName
    target: PathString
    declared_crc32: Crc32
    actual_crc32: Crc32 | None = None
    actual_sha256: Sha256 | None = None
    record: ExtractionRecord | None = None
    detail: str

    @property
    def needs_work(self) -> bool:
        return self.state.needs_work


def digests_of(path: Path) -> tuple[int, str]:
    """Return (crc32, sha256) for a file in a SINGLE pass.

    NOT hashlib.file_digest, despite it being the modern one-liner: it computes
    one digest and consumes the file, so getting both would mean reading 198MB
    twice to checksum the same bytes.

    readinto with a reused buffer rather than read(), which would allocate a
    fresh 8MiB object per chunk for no benefit.
    """
    crc = 0
    sha = hashlib.sha256()
    buffer = bytearray(_COPY_BYTES)
    view = memoryview(buffer)
    with path.open("rb", buffering=0) as handle:
        while (count := handle.readinto(buffer)) > 0:
            chunk = view[:count]
            crc = binascii.crc32(chunk, crc)
            sha.update(chunk)
    return crc & _CRC_MASK, sha.hexdigest()


def crc32_of(path: Path) -> int:
    """CRC-32 only, for callers that need just the cheap transport check."""
    return digests_of(path)[0]


def _archive_digest(archive: Path) -> str:
    """SHA-256 of the archive, reused from the fetch manifest when available.

    The manifest already attests this digest, so recomputing it over 283MB on
    every extraction is pure waste. Computing it as a fallback keeps the
    function correct for an archive that arrived by some other route.
    """
    manifest_file = IngestManifest.path_for(archive)
    if manifest_file.is_file():
        try:
            return IngestManifest.model_validate_json(manifest_file.read_text()).sha256
        except (ValidationError, ValueError, UnicodeDecodeError):
            pass
    return digests_of(archive)[1]


def _member_info(archive: Path, member: str) -> zipfile.ZipInfo:
    """Resolve a member to exactly one entry.

    Deliberately NOT bundle.getinfo(member): with duplicate filenames CPython's
    name index keeps only the last entry, so getinfo silently picks one of
    several and the digest we record would attest bytes another reader might not
    get. resolve_unique_member refuses instead.
    """
    with zipfile.ZipFile(archive) as bundle:
        return resolve_unique_member(bundle, member)


def _leftover_staging(target: Path) -> list[Path]:
    """Staging files beside `target` from runs that did not finish.

    Matches BOTH conventions: the unique per-run name written now, and the fixed
    name used before staging became unique. A pipeline upgraded in place still
    holds leftovers in the old form, and garbage the sweep cannot see is garbage
    that never gets collected.
    """
    unique = target.parent.glob(f"{target.name}.*{STAGING_SUFFIX}")
    legacy = target.with_name(target.name + STAGING_SUFFIX)
    found = set(unique)
    if legacy.exists():
        found.add(legacy)
    return sorted(found)


def _read_record(record_file: Path) -> ExtractionRecord | None:
    """Load a sidecar, or None if absent or unusable.

    Unusable is deliberately equivalent to absent. A sidecar that cannot be
    parsed carries no trustworthy claim, so honouring it means trusting unknown
    metadata, and raising on it strands a pipeline that can redo one step.
    """
    if not record_file.is_file():
        return None
    try:
        # THE ONLY PLACE A SIDECAR IS PARSED. Version handling belongs here and
        # nowhere else: letting each caller branch on schema_version is the
        # documented antipattern, because the branches multiply and drift. When
        # v2 exists, this function upcasts to the current model and every caller
        # keeps working unchanged.
        return ExtractionRecord.model_validate_json(record_file.read_text())
    except (ValidationError, ValueError, UnicodeDecodeError):
        # Includes a sidecar written by a NEWER version: an unknown
        # schema_version fails the Literal, so it is treated as unreadable and
        # the step is redone rather than misinterpreted.
        return None


def _status(
    *,
    state: ExtractionState,
    member: str,
    target: Path,
    declared_crc32: int,
    detail: str,
    actual_crc32: int | None = None,
    actual_sha256: str | None = None,
    record: ExtractionRecord | None = None,
) -> ExtractionStatus:
    """Build a status with the shared fields explicit and typed.

    A `**common` dict would read more concisely and be strictly worse: unpacking
    dict[str, object] into a typed __init__ is uncheckable, so every field would
    lose static verification at each call site.
    """
    return ExtractionStatus(
        state=state,
        member=member,
        target=str(target),
        declared_crc32=declared_crc32,
        actual_crc32=actual_crc32,
        actual_sha256=actual_sha256,
        record=record,
        detail=detail,
    )


def inspect_extraction(archive: Path, member: str, dest_dir: Path) -> ExtractionStatus:
    """Resolve the state of `member` in `dest_dir` without extracting.

    Takes no lock: this is a cheap read, and a caller that only reports state
    should not block a writer. A caller intending to ACT must re-resolve under
    the lock, which extract_member does.
    """
    target = dest_dir / Path(member).name
    declared = _member_info(archive, member).CRC & _CRC_MASK

    if not target.is_file():
        if _leftover_staging(target):
            return _status(
                state=ExtractionState.STAGED,
                member=member,
                target=target,
                declared_crc32=declared,
                detail="staging files survive from an interrupted run",
            )
        return _status(
            state=ExtractionState.ABSENT,
            member=member,
            target=target,
            declared_crc32=declared,
            detail="no data file present",
        )

    record = _read_record(ExtractionRecord.path_for(target))
    if record is None:
        return _status(
            state=ExtractionState.ORPHANED,
            member=member,
            target=target,
            declared_crc32=declared,
            detail="data present but its sidecar is missing or unreadable",
        )

    if record.crc32 != declared:
        return _status(
            state=ExtractionState.STALE,
            member=member,
            target=target,
            declared_crc32=declared,
            record=record,
            detail=(
                f"sidecar records {record.crc32:#010x} but the archive now "
                f"declares {declared:#010x}; the source changed"
            ),
        )

    # One read, both checksums. CRC is evaluated first so a damaged file is
    # reported as transport corruption rather than as a digest mismatch, which
    # would wrongly suggest substitution.
    actual_crc, actual_sha = digests_of(target)
    if actual_crc != declared:
        return _status(
            state=ExtractionState.CORRUPT,
            member=member,
            target=target,
            declared_crc32=declared,
            actual_crc32=actual_crc,
            actual_sha256=actual_sha,
            record=record,
            detail=(
                f"file on disk is {actual_crc:#010x} but both archive and "
                f"sidecar say {declared:#010x}"
            ),
        )

    # THE INTEGRITY CHECK. A CRC match proves only that 32 bits agree, and CRC
    # collisions are trivial to construct, so content substituted after
    # extraction can preserve it. Only the digest detects that.
    #
    # Plain == rather than compare_digest: these are integrity values, not
    # secrets. compare_digest defends a value the attacker must not learn; here
    # the attacker already holds the file.
    if actual_sha != record.sha256:
        return _status(
            state=ExtractionState.CORRUPT,
            member=member,
            target=target,
            declared_crc32=declared,
            actual_crc32=actual_crc,
            actual_sha256=actual_sha,
            record=record,
            detail=(
                "CRC matches but SHA-256 does not: sidecar records "
                f"{record.sha256[:16]}..., file is {actual_sha[:16]}..."
            ),
        )

    return _status(
        state=ExtractionState.COMMITTED,
        member=member,
        target=target,
        declared_crc32=declared,
        actual_crc32=actual_crc,
        actual_sha256=actual_sha,
        record=record,
        detail="archive, sidecar, and file agree on both CRC and SHA-256",
    )


def extract_member(
    archive: Path,
    member: str,
    dest_dir: Path,
    *,
    force: bool = False,
    policy: ExtractionPolicy | None = None,
) -> ExtractionRecord:
    """Drive `member` to COMMITTED, doing nothing if it is already there.

    Everything from the state check to the sidecar publish runs under an
    exclusive lock. Checking outside the lock and acting on the answer is the
    classic TOCTOU race: two agents both see ABSENT, both extract, both publish.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    active_policy = policy or ExtractionPolicy()

    # Refuse a hostile NAME before it is ever used to build a path. Rejecting
    # rather than silently taking the basename keeps two members from
    # collapsing onto one output file.
    target = dest_dir / safe_member_name(member)
    record_file = ExtractionRecord.path_for(target)

    with exclusive_lock(target):
        # Re-resolve INSIDE the lock. Any status read before acquiring it was
        # advisory and may already be out of date.
        status = inspect_extraction(archive, member, dest_dir)
        if not force and status.state is ExtractionState.COMMITTED:
            if status.record is None:  # pragma: no cover - COMMITTED implies a record
                raise AssertionError("COMMITTED status without a sidecar record")
            return status.record

        declared = status.declared_crc32

        # Sweep leftovers from runs that died before publishing. Holding the
        # lock is what makes this safe: no live writer can own them.
        for stale in _leftover_staging(target):
            stale.unlink(missing_ok=True)

        # Unique staging name: mkstemp relies on O_EXCL, so no two runs receive
        # the same path even if the lock were somehow bypassed.
        staged = new_staging_path(target)
        try:
            # Archive-level limits first: member count, declared total, overlap.
            check_archive(archive, active_policy)

            with zipfile.ZipFile(archive) as bundle:
                # Exactly one entry, or refuse. See _member_info.
                info = resolve_unique_member(bundle, member)
                # Declared metadata: advisory, and cheap enough to be worth it.
                check_member(info, dest_dir, active_policy)

                # open(info), NOT open(member). Passing the resolved ZipInfo is
                # what makes the entry inspected provably the entry read.
                with bundle.open(info) as source, staged.open("wb") as sink:
                    # NOT copyfileobj. The loop exists so every chunk can be
                    # counted and the write aborted the instant a real limit is
                    # crossed; copyfileobj cannot see the policy.
                    written = 0
                    crc = 0
                    sha = hashlib.sha256()
                    while chunk := source.read(_COPY_BYTES):
                        written += len(chunk)
                        enforce_while_writing(written, info.compress_size, info, active_policy)
                        # Digest AS the bytes are written. Re-reading the
                        # published file afterwards would double the I/O and,
                        # worse, attest whatever is on disk THEN rather than
                        # what was actually extracted from this archive.
                        crc = binascii.crc32(chunk, crc)
                        sha.update(chunk)
                        sink.write(chunk)
                    crc &= _CRC_MASK
                    member_sha = sha.hexdigest()

            # Verify BEFORE publishing. A corrupt member must never appear under
            # the real name, because everything downstream treats the raw layer
            # as truth.
            if crc != declared:
                raise ValueError(
                    f"CRC mismatch extracting {member!r}: archive declares "
                    f"{declared:#010x}, extracted data is {crc:#010x}"
                )

            publish(staged, target)
        except BaseException:
            # Never leave staging garbage behind on a failed run.
            staged.unlink(missing_ok=True)
            raise

        # PHASE 2: the sidecar is the commit point. Until it lands the data
        # above is ORPHANED, and the next run redoes this step.
        record = ExtractionRecord(
            archive=str(archive),
            member=member,
            size_bytes=target.stat().st_size,
            sha256=member_sha,
            archive_sha256=_archive_digest(archive),
            crc32=declared,
            extracted_at=datetime.now(UTC),
        )
        write_atomic(record_file, record.model_dump_json(indent=2))
        return record
