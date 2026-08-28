# src/spark_batch_pipeline/ingest/fetch.py
"""Idempotent, checksummed, resumable download of source artifacts.

WHY THIS EXISTS: the PDF downloads WDI_CSV.zip inside a notebook cell. That
artifact is 283 MB, so every re-run re-fetches it, nothing records what was
actually retrieved, and a stalled connection hangs forever. None of that is
acceptable in a raw layer whose job is to be the replayable source of truth.

Guarantees:

IDEMPOTENT   A completed fetch with a matching manifest is skipped. A re-run
             costs a checksum pass over local disk, not 283 MB of transfer.
RESUMABLE    Partial downloads persist as `.part` and resume via an HTTP Range
             request. A drop at 250 MB does not restart from zero.
BOUNDED      Explicit connect/read timeouts plus bounded retries with
             exponential backoff. A hung socket fails in seconds, not never.
ATTESTED     Each fetch writes a manifest with url, sha256, size, server ETag
             and Last-Modified, and the UTC ingestion time. The bronze contract
             is an ingestion timestamp, a source identifier, and a checksum
             validating integrity against source -- without those, "reprocess
             from raw" is an act of faith.
ATOMIC       The artifact appears at its final path only when complete, so no
             reader ever observes a half-written raw file.

HTTP CLIENT: httpx, not requests (feature-frozen, no HTTP/2) and not urllib
(no timeouts or retries without hand-rolling both).

REDIRECTS ARE NOT OPTIONAL HERE: httpx does NOT follow redirects by default,
and databank.worldbank.org 301s to databankfiles.worldbank.org. Without
follow_redirects=True this writes a 193-byte HTML redirect stub and reports
success. That failure is silent, which is what makes it dangerous.

Bytes are written exactly as received. No parsing, no filtering: that is the
raw layer contract, and it is what makes reprocessing meaningful.
"""

from __future__ import annotations

import hashlib
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
from pydantic import BaseModel, ConfigDict, Field

# 8 MiB blocks: syscall overhead is negligible on a 283 MB file, and memory
# stays flat regardless of artifact size.
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

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_name: str
    url: str
    filename: str
    size_bytes: int = Field(ge=0)
    sha256: str = Field(min_length=64, max_length=64)
    etag: str | None = None
    last_modified: str | None = None
    ingested_at: datetime

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
    partial = artifact.with_name(artifact.name + ".part")

    # Fast path: a prior run completed this fetch. Re-verify the digest -- a
    # manifest whose artifact was truncated is worse than none, because it
    # asserts an integrity guarantee that no longer holds.
    if manifest_file.exists() and artifact.exists() and not force:
        existing = IngestManifest.model_validate_json(manifest_file.read_text())
        if sha256_of(artifact) == existing.sha256:
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
                # Connection reset or read timeout: whatever landed in .part is
                # kept, and the next attempt resumes from that offset.
                if attempt == _MAX_ATTEMPTS - 1:
                    raise
                _sleep_backoff(attempt)
    finally:
        if owns_client:
            active.close()

    shutil.move(str(partial), str(artifact))

    manifest = IngestManifest(
        source_name=source_name,
        url=url,
        filename=name,
        size_bytes=artifact.stat().st_size,
        sha256=sha256_of(artifact),
        etag=headers.get("etag"),
        last_modified=headers.get("last-modified"),
        ingested_at=datetime.now(UTC),
    )
    manifest_file.write_text(manifest.model_dump_json(indent=2))
    return manifest
