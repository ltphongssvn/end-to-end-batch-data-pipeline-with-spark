# src/spark_batch_pipeline/ingest/fetch.py
"""Idempotent, checksummed, resumable download of source artifacts.

WHY THIS EXISTS: the PDF downloads WDI_CSV.zip inside a notebook cell. That
artifact is 283 MB, so every re-run re-fetches it, nothing records what was
actually retrieved, and a stalled connection hangs forever. None of that is
acceptable in a raw layer whose job is to be the replayable source of truth.

Guarantees:

IDEMPOTENT   A completed fetch with a matching manifest is skipped. A re-run
             costs a checksum pass over local disk, not 283 MB of transfer.
RESUMABLE    Partial downloads persist as a staged file and resume via an HTTP
             Range request. A drop at 250 MB does not restart from zero.
BOUNDED      Explicit connect/read timeouts plus bounded retries with
             exponential backoff. A hung socket fails in seconds, not never.
ATTESTED     Each fetch writes a manifest with url, sha256, size, server ETag
             and Last-Modified, and the UTC ingestion time. The bronze contract
             is an ingestion timestamp, a source identifier, and a checksum
             validating integrity against source -- without those, "reprocess
             from raw" is an act of faith.

COMMIT PROTOCOL, both phases symmetrical:
    stage bytes    -> publish artifact  (atomic + durable)
    render manifest -> publish manifest (atomic + durable)
The artifact is published first, so a crash between the phases leaves ORPHAN
DATA: a complete file that no manifest references. That is the Iceberg model
and it is the safe direction of failure, because the next run redoes the step.

A truncated manifest would be worse than a missing one -- missing means "redo",
truncated means the next run dies parsing it. So the manifest is published
atomically, and an unreadable manifest is treated as absent rather than fatal.

HTTP CLIENT: httpx, not requests (feature-frozen, no HTTP/2) and not urllib
(no timeouts or retries without hand-rolling both).

REDIRECTS ARE NOT OPTIONAL HERE: httpx does NOT follow redirects by default,
and databank.worldbank.org 301s to databankfiles.worldbank.org. Without
follow_redirects=True this writes a 193-byte HTML redirect stub and reports
success. That failure is silent, which is what makes it dangerous.

CONCURRENCY: the staging name is STABLE, because resuming a 283MB download
requires the partial to keep the same name across process restarts. A stable
name is shared by every invocation, so two agents would both open it, both
append, and interleave their bytes into one corrupt file -- which the sha256
check would catch only after the whole transfer. exclusive_lock therefore covers
the entire check-fetch-publish sequence. Unlike extract.py, a unique staging
name is NOT an option here: it would trade resumability for safety when the lock
already provides safety without that cost.

Bytes are written exactly as received. No parsing, no filtering: that is the
raw layer contract, and it is what makes reprocessing meaningful.
"""

from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from spark_batch_pipeline.atomicio import (
    exclusive_lock,
    publish,
    staging_path,
    write_atomic,
)
from spark_batch_pipeline.runcontext import current_run
from spark_batch_pipeline.valuetypes import (
    ByteCount,
    PathString,
    RecordedUrl,
    Sha256,
    UtcTimestamp,
)

# 8 MiB blocks: syscall overhead is negligible on a 283 MB file, and memory
# stays flat regardless of artifact size.
# VERSIONED CONTRACT, matching ExtractionRecord. A manifest outlives the code
# that wrote it, and extract.py copies its sha256 forward into archive_sha256 --
# so an unversioned manifest leaves the chain of custody unreadable to any
# future reader that cannot tell which shape it is holding.
#
# Defaulted, the non-breaking form: existing manifests have exactly the v1 field
# set, so reading them as v1 is accurate rather than a fudge. When v2 arrives,
# add a new literal instead of repurposing this one -- changing the meaning of
# an existing default silently rewrites every historical record.
type IngestManifestVersion = Literal["ingest-manifest/v1"]
INGEST_MANIFEST_VERSION: Final[IngestManifestVersion] = "ingest-manifest/v1"

_CHUNK_BYTES = 8 * 1024 * 1024

# Separate connect and read budgets. A read timeout must tolerate a slow origin
# mid-transfer; a connect timeout should fail fast on an unreachable host.
DEFAULT_TIMEOUT = httpx.Timeout(connect=15.0, read=120.0, write=30.0, pool=15.0)

# Retry only what is plausibly transient. A 404 is a configuration error and
# retrying it just delays the real message -- which is exactly how we found the
# WDI_csv.zip rename.
_RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})
_MAX_ATTEMPTS = 5
_BACKOFF_BASE_SECONDS = 1.5


class IngestManifest(BaseModel):
    """Provenance record for one fetched artifact."""

    # strict, matching ExtractionRecord: an attestation must not be assembled
    # from coerced input. Pydantic is looser from JSON by design, so ingested_at
    # still parses from an ISO string and the manifest round trip is unaffected.
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    # First field so it is the first key a human sees in the JSON.
    schema_version: IngestManifestVersion = INGEST_MANIFEST_VERSION

    # OBSERVABILITY, NOT INTEGRITY. These answer "which orchestrated run
    # produced this, and by whom" -- the question the digest chain cannot. The
    # causation edge already exists as a content digest rather than an opaque
    # id, which is stronger: it proves the link instead of asserting it.
    #
    # NULLABLE RATHER THAN DEFAULTED, deliberately. Forcing a value on a field
    # that may genuinely be unknown is the documented anti-pattern: the writer
    # is obliged to produce something, so it fabricates. A record written
    # before these fields existed has UNKNOWN provenance, and null says exactly
    # that. Omitted and null mean the same thing here -- not recorded -- so no
    # three-state distinction is needed.
    #
    # run_id is W3C trace-id shaped, so adopting OpenTelemetry later is a
    # rename rather than a migration.
    run_id: PathString | None = None
    actor: PathString | None = None

    source_name: PathString
    filename: PathString

    # Verbatim, not HttpUrl. HttpUrl belongs in conf/pipeline.yml where the job
    # is to REJECT bad input; here the job is to RECORD what happened, and a
    # normalizing type could store a URL that was never requested.
    url: RecordedUrl

    size_bytes: ByteCount

    # THE ROOT OF TRUST. Sha256 requires 64 lowercase HEX digits; the previous
    # min_length/max_length pair accepted ANY 64 characters, so a manifest
    # corrupted to the right length passed as a valid attestation. extract.py
    # copies this value into archive_sha256, so a weak constraint here weakened
    # the entire chain of custody.
    sha256: Sha256

    # Deliberately unconstrained: these are verbatim SERVER headers, not values
    # this project produces. Their format is the origin's business, and imposing
    # a shape would reject a legitimate response.
    etag: str | None = None
    last_modified: str | None = None

    # Timezone-aware: a naive timestamp cannot order two manifests written on
    # machines in different zones.
    ingested_at: UtcTimestamp

    @staticmethod
    def path_for(artifact: Path) -> Path:
        return artifact.with_name(artifact.name + ".manifest.json")


def sha256_of(path: Path) -> str:
    """Stream a file through SHA-256 without loading it into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _read_manifest(manifest_file: Path) -> IngestManifest | None:
    """Load a manifest, or None if it is absent or unusable.

    Unusable is deliberately equivalent to absent. A manifest that cannot be
    parsed carries no trustworthy claim, so honouring it would mean trusting
    unknown metadata, and raising on it would strand a pipeline that can simply
    redo one step.
    """
    if not manifest_file.is_file():
        return None
    try:
        # THE ONLY PLACE A MANIFEST IS PARSED. Version handling belongs here and
        # nowhere else: letting each caller branch on schema_version is the
        # documented antipattern, because the branches multiply and drift. When
        # v2 exists this function upcasts, and callers keep working unchanged.
        return IngestManifest.model_validate_json(manifest_file.read_text())
    except (ValidationError, ValueError, UnicodeDecodeError):
        # Includes a manifest written by a NEWER version: an unknown
        # schema_version fails the Literal, so it is treated as unreadable and
        # the fetch is redone rather than misinterpreted.
        #
        # Deliberately NOT tolerant-reader. Ignoring unknown fields suits
        # long-lived consumers evolving independently of producers; here the
        # reader IS the writer, and the artifact is an attestation. Trusting a
        # claim we cannot interpret is worse than repeating cheap work.
        return None


def _sleep_backoff(attempt: int) -> None:
    time.sleep(_BACKOFF_BASE_SECONDS**attempt)


def _stream_to_part(
    client: httpx.Client, url: str, partial: Path, resume_from: int
) -> tuple[dict[str, str], bool]:
    """Stream one attempt into `partial`. Returns (headers, appended)."""
    headers = {"Range": f"bytes={resume_from}-"} if resume_from else {}

    with client.stream("GET", url, headers=headers) as response:
        if response.status_code in _RETRYABLE_STATUS:
            response.raise_for_status()
        response.raise_for_status()

        # 206 means the server honoured Range. Any other success code means it
        # is sending the whole body, so appending would corrupt the file.
        appended = response.status_code == 206 and resume_from > 0
        mode = "ab" if appended else "wb"
        with partial.open(mode) as out:
            for chunk in response.iter_bytes(_CHUNK_BYTES):
                out.write(chunk)
        return dict(response.headers), appended


def fetch_source(
    *,
    source_name: str,
    url: str,
    dest_dir: Path,
    filename: str | None = None,
    client: httpx.Client | None = None,
    force: bool = False,
) -> IngestManifest:
    """Download `url` into `dest_dir`, or return the existing manifest.

    Pass `client` to inject an httpx.Client (tests use httpx.MockTransport, so
    the suite needs no network -- a test suite that needs the internet is one
    that fails on a plane). Set `force=True` to re-download unconditionally.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = filename or url.rsplit("/", 1)[-1]
    artifact = dest_dir / name
    manifest_file = IngestManifest.path_for(artifact)
    # Stable staging name: resuming across process restarts needs it. Safe only
    # because the lock below serialises writers.
    partial = staging_path(artifact)

    with exclusive_lock(artifact):
        return _fetch_locked(
            source_name=source_name,
            url=url,
            artifact=artifact,
            manifest_file=manifest_file,
            partial=partial,
            name=name,
            client=client,
            force=force,
        )


def _fetch_locked(
    *,
    source_name: str,
    url: str,
    artifact: Path,
    manifest_file: Path,
    partial: Path,
    name: str,
    client: httpx.Client | None,
    force: bool,
) -> IngestManifest:
    """The critical section. Only ever called while holding the artifact lock.

    Split out so the lock scope is visible in one place rather than indenting
    the whole body: everything here -- the completeness check, the transfer, and
    both publishes -- must be serialised. Checking outside the lock and acting
    on the answer is the classic TOCTOU race.
    """
    # Fast path: a prior run completed this fetch. Re-verify the digest -- a
    # manifest whose artifact was truncated is worse than none, because it
    # asserts an integrity guarantee that no longer holds.
    if not force and artifact.is_file():
        existing = _read_manifest(manifest_file)
        if existing is not None and sha256_of(artifact) == existing.sha256:
            return existing

    if force and partial.exists():
        partial.unlink()

    owns_client = client is None
    # follow_redirects=True is load-bearing; see the module docstring.
    active = client or httpx.Client(timeout=DEFAULT_TIMEOUT, follow_redirects=True)

    try:
        headers: dict[str, str] = {}
        for attempt in range(_MAX_ATTEMPTS):
            resume_from = partial.stat().st_size if partial.exists() else 0
            try:
                headers, _ = _stream_to_part(active, url, partial, resume_from)
                break
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code not in _RETRYABLE_STATUS:
                    raise
                if attempt == _MAX_ATTEMPTS - 1:
                    raise
                _sleep_backoff(attempt)
            except httpx.TransportError:
                # Connection reset or read timeout: whatever landed in the
                # staged file is kept, and the next attempt resumes from there.
                if attempt == _MAX_ATTEMPTS - 1:
                    raise
                _sleep_backoff(attempt)
    finally:
        if owns_client:
            active.close()

    # PHASE 1: fsync the staged bytes, atomic same-directory replace, fsync the
    # parent so the NAME is durable too.
    publish(partial, artifact)

    # PHASE 2: the manifest is the commit point. Until it lands, the artifact
    # above is an orphan and the next run re-fetches.
    manifest = IngestManifest(
        run_id=current_run().run_id,
        actor=current_run().actor,
        source_name=source_name,
        url=url,
        filename=name,
        size_bytes=artifact.stat().st_size,
        sha256=sha256_of(artifact),
        etag=headers.get("etag"),
        last_modified=headers.get("last-modified"),
        ingested_at=datetime.now(UTC),
    )
    write_atomic(manifest_file, manifest.model_dump_json(indent=2))
    return manifest
