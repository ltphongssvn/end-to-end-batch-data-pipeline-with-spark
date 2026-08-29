# src/spark_batch_pipeline/ingest/extract.py
"""Extract archive members into the raw layer, as an explicit state machine.

WHY THIS IS NOT OPTIONAL: Spark reads gzip and bzip2 natively but NOT zip.
WDI_CSV.zip must be expanded before any DataFrame can touch it, and the member
is 198MB, so re-running must not repeat the work.

WHY A STATE MACHINE RATHER THAN NESTED CONDITIONS
The states below always existed -- ABSENT, STAGED, ORPHANED, STALE, CORRUPT,
COMMITTED -- but were encoded implicitly in file existence and one compound
boolean. Implicit states cannot be inspected without performing the work, cannot
be asserted individually, and cannot be reported to a supervising process
deciding what to do next. inspect_extraction() resolves the state WITHOUT
extracting anything, so the decision and the action are separable.

    ABSENT     no data file. Nothing has happened yet.
    STAGED     staging files survive from a run that died mid-write. Garbage to
               be cleaned, not a partial to resume: a zip member cannot be
               inflated from an arbitrary offset.
    ORPHANED   data present, sidecar missing or unparseable. The phase-1 crash
               window: complete bytes that nothing references. This is the SAFE
               direction of failure and is simply redone.
    STALE      sidecar readable but its CRC disagrees with what the archive now
               declares. The source changed under us.
    CORRUPT    sidecar agrees with the archive, but the file on disk does not
               match either. Bit rot or an edit in place.
    COMMITTED  archive, sidecar, and file all agree. The only state that skips
               work.

CONCURRENCY: idempotent-under-sequential-execution and safe-under-concurrency
are different properties, and this module needs both. Two agents extracting the
same member would previously open the same fixed "<name>.part", truncate it,
and race on the rename. The whole check-and-commit sequence therefore runs under
exclusive_lock: without the lock, both would observe the same state, both would
do the work, and both would publish. The staging name is also unique per run, so
a dead run's leftovers can never be mistaken for the current one.

The state is resolved TWICE on purpose -- once outside the lock for a cheap
answer, once inside before acting. The first is advisory and can be stale by the
time it returns; only the second is a decision.

COMMIT PROTOCOL, both phases symmetrical:
    stage data     -> verify CRC -> publish data     (atomic + durable)
    render sidecar ->              publish sidecar   (atomic + durable)
Data is published first, so a crash between phases yields ORPHANED, never a
sidecar describing data that was never written. That is the Iceberg ordering:
orphan files are recoverable, dangling pointers are not.

WHY A STALE SIDECAR CANNOT BE TRUSTED AFTER AN OVERWRITE: the sidecar's claim is
checked against BOTH the archive's declared CRC and the file's actual CRC, so it
cannot certify content it does not describe.

IDEMPOTENCE, and why size is not enough: length comparison accepts a file edited
in place without a length change. Zip stores a CRC per member, so verification
costs one pass over local disk and no re-inflation.

CRC comes from binascii, not zipfile. zipfile.crc32 exists at runtime only as a
private re-export of binascii.crc32; depending on it is depending on an
implementation detail, which is what mypy flags. Same function, public name.

ZERO-TRUST DECOMPRESSION: an archive fetched over the network is untrusted
input, so inflation is policy-controlled (see policy.py). The critical point is
that `info.file_size` is a field IN the archive and therefore attacker
controlled -- checking it is a cheap early reject, never the guarantee. The
binding limit is a byte counter that aborts mid-write, so an archive that lies
in its header is stopped before it fills the volume rather than after.

STAYS RAW: bytes are written exactly as stored. No parsing, re-encoding, or
newline translation. The raw layer is only replayable if what lands is what the
source shipped.
"""

from __future__ import annotations

import binascii
import zipfile
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, NonNegativeInt, ValidationError

from spark_batch_pipeline.atomicio import (
    STAGING_SUFFIX,
    exclusive_lock,
    new_staging_path,
    publish,
    write_atomic,
)
from spark_batch_pipeline.ingest.policy import (
    ExtractionPolicy,
    check_archive,
    check_member,
    enforce_while_writing,
    resolve_unique_member,
    safe_member_name,
)

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
    """Sidecar proving which member produced a given raw file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    archive: str
    member: str
    size_bytes: NonNegativeInt
    crc32: int = Field(ge=0, le=_CRC_MASK)
    extracted_at: datetime

    @staticmethod
    def path_for(target: Path) -> Path:
        return target.with_name(target.name + ".extract.json")


class ExtractionStatus(BaseModel):
    """Resolved state of one member, computed without extracting anything."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: ExtractionState
    member: str
    target: str
    declared_crc32: int = Field(ge=0, le=_CRC_MASK)
    actual_crc32: int | None = None
    record: ExtractionRecord | None = None
    detail: str

    @property
    def needs_work(self) -> bool:
        return self.state.needs_work


def _member_info(archive: Path, member: str) -> zipfile.ZipInfo:
    """Resolve a member to exactly one entry.

    Deliberately NOT bundle.getinfo(member): with duplicate filenames CPython's
    name index keeps only the last entry, so getinfo silently picks one of
    several and the CRC we record would attest bytes another reader might not
    get. resolve_unique_member refuses instead.
    """
    with zipfile.ZipFile(archive) as bundle:
        return resolve_unique_member(bundle, member)


def crc32_of(path: Path) -> int:
    """CRC-32 of a file, computed the way zip computes it."""
    crc = 0
    with path.open("rb") as handle:
        while chunk := handle.read(_COPY_BYTES):
            crc = binascii.crc32(chunk, crc)
    return crc & _CRC_MASK


def _leftover_staging(target: Path) -> list[Path]:
    """Staging files beside `target` from runs that did not finish.

    Matches BOTH conventions: the unique per-run name this module writes now
    ("<name>.<random>.part") and the fixed name it used before staging became
    unique ("<name>.part"). A pipeline upgraded in place will still be holding
    leftovers in the old form, and garbage that the sweep cannot see is garbage
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
        return ExtractionRecord.model_validate_json(record_file.read_text())
    except (ValidationError, ValueError, UnicodeDecodeError):
        return None


def _status(
    *,
    state: ExtractionState,
    member: str,
    target: Path,
    declared_crc32: int,
    detail: str,
    actual_crc32: int | None = None,
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
        record=record,
        detail=detail,
    )


def inspect_extraction(archive: Path, member: str, dest_dir: Path) -> ExtractionStatus:
    """Resolve the state of `member` in `dest_dir` without extracting.

    Takes no lock: this is a cheap read, and a caller that only reports state
    should not block a writer. A caller that intends to ACT on the answer must
    re-resolve under the lock, which extract_member does.
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

    actual = crc32_of(target)
    if actual != declared:
        return _status(
            state=ExtractionState.CORRUPT,
            member=member,
            target=target,
            declared_crc32=declared,
            actual_crc32=actual,
            record=record,
            detail=(
                f"file on disk is {actual:#010x} but both archive and sidecar say {declared:#010x}"
            ),
        )

    return _status(
        state=ExtractionState.COMMITTED,
        member=member,
        target=target,
        declared_crc32=declared,
        actual_crc32=actual,
        record=record,
        detail="archive, sidecar, and file all agree",
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
    classic TOCTOU race: two agents both see ABSENT, both extract, and both
    publish.
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
        # advisory and may already be out of date -- another agent may have
        # completed the whole extraction while we waited.
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

        # Unique staging name: mkstemp relies on O_EXCL, so no two runs can
        # receive the same path even if the lock were somehow bypassed.
        staged = new_staging_path(target)
        try:
            # PHASE 1: inflate, then verify BEFORE publishing. A corrupt member
            # must never appear under the real name, because everything
            # downstream treats the raw layer as truth.
            # Archive-level limits first: member count and declared total.
            check_archive(archive, active_policy)

            with zipfile.ZipFile(archive) as bundle:
                # Exactly one entry, or refuse. See _member_info.
                info = resolve_unique_member(bundle, member)
                # Declared metadata: advisory, and cheap enough to be worth it.
                check_member(info, dest_dir, active_policy)

                # open(info), NOT open(member). Passing the resolved ZipInfo is
                # what makes the entry we inspected provably the entry we read;
                # a name would be re-resolved and could bind elsewhere.
                with bundle.open(info) as source, staged.open("wb") as sink:
                    # NOT copyfileobj. The loop exists so every chunk can be
                    # counted and the write aborted the instant a real limit is
                    # crossed. copyfileobj would happily stream a bomb to
                    # completion because it cannot see the policy.
                    written = 0
                    while chunk := source.read(_COPY_BYTES):
                        written += len(chunk)
                        enforce_while_writing(written, info.compress_size, info, active_policy)
                        sink.write(chunk)

            actual = crc32_of(staged)
            if actual != declared:
                raise ValueError(
                    f"CRC mismatch extracting {member!r}: archive declares "
                    f"{declared:#010x}, extracted data is {actual:#010x}"
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
            crc32=declared,
            extracted_at=datetime.now(UTC),
        )
        write_atomic(record_file, record.model_dump_json(indent=2))
        return record
