# src/spark_batch_pipeline/ingest/acquire.py
"""The acquisition boundary, as one call.

    acquire_source()
        fetch   -> archive committed, sha256 attested
        extract -> member committed, digest chained to the archive
        ready   -> RawArtifact: a URI that may now be read

    A consumer then reads that URI. It CONSUMES state; it does not own the side
    effect that produced it.

WHY THIS MODULE EXISTS. The steps were already correct and nothing composed
them: `fetch_source` had no caller anywhere in the package, so the correct
sequence lived in whichever ad-hoc script someone wrote next. That is how a
boundary erodes -- not by anyone deciding to break it, but by the right order
never being expressible as a single call.

WHERE THIS SITS. This is the APPLICATION layer in a ports-and-adapters shape:
it orchestrates fetch, extract, publish and announce, and delegates every piece
of real work to the modules that own it. A Dagster asset is a DRIVING ADAPTER
that calls this; it is not where the logic lives.

No formal Port abstractions are introduced, deliberately. The injected
httpx.Client already is one, and defining interfaces for a single
implementation is the ceremony that gives the pattern a bad name. What matters
is the property, not the vocabulary: this module imports no orchestrator, so
the tests exercise the real thing and swapping orchestrators rewrites an asset
definition rather than a pipeline.

THREE INDEPENDENT REASONS ACQUISITION MUST FINISH BEFORE SPARK STARTS, each
sufficient alone:

  Speculative execution. A task judged slow is duplicated on another node and
  whichever finishes first wins, so a side effect inside a transformation runs
  an unpredictable number of times BY DESIGN, not merely on failure.

  Task retry. A failed task re-runs, repeating whatever it already did.

  LAZY EVALUATION ITSELF. A transformation may execute several times when more
  than one action references it in the lineage -- no failure, no speculation.
  Referencing a DataFrame twice is enough.

atomicio's locks and atomic publishes make all three SAFE without making them
CORRECT: the bytes land intact, and a 283MB download still runs repeatedly
while the extraction policy decision is taken once per attempt rather than once
per artifact. Safety is not the same as doing the work once.
"""

from __future__ import annotations

from pathlib import Path
from time import perf_counter
from typing import Final, Literal

import httpx
from pydantic import BaseModel, ConfigDict

from spark_batch_pipeline.ingest.extract import ExtractionRecord, extract_member
from spark_batch_pipeline.ingest.fetch import IngestManifest, fetch_source
from spark_batch_pipeline.telemetry import EventName, Outcome, emit, event
from spark_batch_pipeline.valuetypes import ByteCount, PathString, Sha256

# Versioned like every other contract here: this crosses a layer boundary, so
# its shape is an interface rather than an implementation detail.
type RawArtifactVersion = Literal["raw-artifact/v1"]
RAW_ARTIFACT_VERSION: Final[RawArtifactVersion] = "raw-artifact/v1"


class RawArtifact(BaseModel):
    """A committed file a consumer may read, with the identity that makes it
    trustworthy.

    RETURNED, not merely announced. An event alone would leave the reader to
    reconstruct a path, which is how a consumer ends up building the filename
    itself and drifting from what was actually written.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: RawArtifactVersion = RAW_ARTIFACT_VERSION

    # Absolute. A relative path resolves against the working directory of
    # whichever process reads it, and a driver need not share the client's.
    uri: PathString

    # The chain of custody carried forward, so a downstream failure traces back
    # to bytes without re-deriving anything.
    member_sha256: Sha256
    archive_sha256: Sha256
    size_bytes: ByteCount

    @property
    def path(self) -> Path:
        return Path(self.uri)


def acquire_source(
    *,
    source_name: str,
    url: str,
    member: str,
    dest_dir: Path,
    client: httpx.Client | None = None,
    force: bool = False,
    limits_override: dict[str, object] | None = None,
) -> RawArtifact:
    """Run the acquisition sequence to completion and return a readable URI.

    SYNCHRONOUS AND EAGER. Everything has finished when this returns: the
    archive committed with its digest attested, the member extracted and
    verified, the policy decision recorded, both sidecars durable. Nothing is
    deferred to a later action.

    `client` is injected for tests, matching fetch_source, so the suite needs
    no network.
    """
    started = perf_counter()

    try:
        return _acquire(
            source_name=source_name,
            url=url,
            member=member,
            dest_dir=dest_dir,
            client=client,
            force=force,
            limits_override=limits_override,
            started=started,
        )
    except Exception as exc:
        # WITHOUT THIS, A FAILURE IS SILENT AT THIS LAYER. fetch and extract
        # each report their own failure, but a consumer waiting on
        # raw_artifact.ready would wait forever with nothing explaining why the
        # handoff never came. The policy caught the omission.
        emit(
            event(
                EventName.ACQUISITION_FAILED,
                source=source_name,
                member=member,
                error_type=type(exc).__name__,
                reason=str(exc),
                duration=perf_counter() - started,
                outcome=Outcome.FAILURE,
            )
        )
        raise


def _acquire(
    *,
    source_name: str,
    url: str,
    member: str,
    dest_dir: Path,
    client: httpx.Client | None,
    force: bool,
    limits_override: dict[str, object] | None,
    started: float,
) -> RawArtifact:
    """The sequence itself, separated so the failure path above stays visible
    in one place rather than indenting the whole body."""
    manifest: IngestManifest = fetch_source(
        source_name=source_name,
        url=url,
        dest_dir=dest_dir,
        client=client,
        force=force,
    )

    record: ExtractionRecord = extract_member(
        dest_dir / manifest.filename,
        member,
        dest_dir,
        force=force,
        limits_override=limits_override,
    )

    target = (dest_dir / member).resolve()

    # THE HANDOFF. Everything upstream is committed at this point, so this is
    # the first moment a consumer may legitimately read the file. It carries
    # the URI precisely so a reader never has to guess it.
    emit(
        event(
            EventName.RAW_ARTIFACT_READY,
            source=source_name,
            member=member,
            member_sha256=record.sha256,
            archive_sha256=record.archive_sha256,
            bytes_total=record.size_bytes,
            uri=str(target),
            # END-TO-END latency. fetch and extract each report their own, and
            # neither answers the question a consumer actually has: how long
            # from asking to being able to read.
            duration=perf_counter() - started,
            outcome=Outcome.SUCCESS,
        )
    )

    return RawArtifact(
        uri=str(target),
        member_sha256=record.sha256,
        archive_sha256=record.archive_sha256,
        size_bytes=record.size_bytes,
    )
