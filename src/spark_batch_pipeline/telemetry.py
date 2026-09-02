# src/spark_batch_pipeline/telemetry.py
"""Telemetry as a contract, not a side effect.

THE GAP THIS CLOSES: before this module the ingestion layer produced exactly two
observable outputs -- a record on success, an exception on failure. Everything
between was invisible: whether a run hit cache or did the work, how long 198MB
took, which policy authorized it, why a member was refused. An operator could
see the result and never the behaviour.

TELEMETRY IS DEFINED, VALIDATED, VERSIONED AND GATED, like every other contract
here and for the same reason. Instrumentation added locally and never validated
drifts: an attribute disappears, a type changes, and nothing notices until an
incident needs it. OpenTelemetry's Weaver exists to fix precisely that by
declaring telemetry schemas explicitly and checking payloads against them. This
project already has that machinery -- Pydantic models published as versioned
JSON Schema behind a drift gate -- so telemetry reuses it instead of growing a
parallel system.

    behaviour       events at every state transition
    contract        PipelineEvent, frozen and strict
    runtime check   every event validated before it is emitted
    tests           assertions that the right events carry the right fields
    CI enforcement  contract drift fails the gate

WHY stdlib logging AND NOT structlog: this is a LIBRARY. structlog is the better
tool for an application, but a library importing it imposes a logging framework
on every consumer. A library must also never configure logging -- no
basicConfig, no handlers, no level -- because that is the caller's decision. A
NullHandler is the documented way to stay silent until an application asks to
listen.

WHY ONE NAMESPACED extra KEY. `extra` unpacks straight into LogRecord.__dict__,
and Python's own docs warn the keys must not clash with the logging system's.
Spreading twelve fields would collide on `name`, `module` and `args`, raising a
KeyError inside the logging call -- taking down the process the telemetry exists
to observe. Nesting the whole event under one key makes that class of failure
impossible, and a JSON formatter or OTel handler still sees real structure.

WHY NOT THE OTel SDK YET. The guidance is to start with one signal and prove it
trustworthy before expanding; instrumenting every signal at once is the named
anti-pattern. There is no collector and no backend here, so an SDK plus
exporters would be machinery around telemetry nobody reads. What matters now is
that the DATA is correct and correlatable -- which is why run_id is already W3C
trace-id shaped. Adopting OTel later maps these fields onto spans without
changing what is recorded.

EVENTS ARE DEFINED BEFORE THE CODE THAT EMITS THEM. That ordering is the whole
of observability-driven development: decide what a feature must make visible,
then implement it. Instrumenting afterwards produces telemetry shaped by
whatever the implementation happened to make easy, which is rarely what an
operator needs at 2am.

SPEC ATTRIBUTES ARE REUSED, NOT REINVENTED. Where OpenTelemetry defines an
attribute -- url.full, error.type, http.request.resend_count -- this model emits
that exact name via serialization_alias, because a backend that already
understands it needs no mapping layer. Anything genuinely local stays in its own
namespace: putting our meaning under http.* would blur spec-defined attributes
with invented ones, and that ambiguity is permanent.

ATTRIBUTE NAMING otherwise follows OpenTelemetry's dotted style. Teams that invent their
own naming end up with telemetry that cannot be correlated, which defeats the
point. No OTel semantic convention covers archive extraction, so `extraction.*`
is a local namespace declared here rather than improvised at each call site.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from spark_batch_pipeline.runcontext import current_run
from spark_batch_pipeline.valuetypes import PathString, UtcTimestamp

# Versioned exactly like the sidecars. An event outlives the code that emitted
# it: it lands in a log store and is queried months later, when the only way to
# know which fields to expect is the version it carries.
# v2, not an edit of v1. Aligning field names onto OpenTelemetry's spec
# attributes renames keys on the wire, which is a breaking change by this
# project's own rule -- so v1 stays published and immutable beside it.
type PipelineEventVersion = Literal["pipeline-event/v3"]
PIPELINE_EVENT_VERSION: Final[PipelineEventVersion] = "pipeline-event/v3"

# getLogger(__name__), and a NullHandler so the library is silent by default.
_LOGGER: Final = logging.getLogger(__name__)
_LOGGER.addHandler(logging.NullHandler())

# The single key everything is nested under. Namespaced so it cannot collide
# with a LogRecord attribute now or in a future Python.
EVENT_KEY: Final = "pipeline_event"


class EventName(StrEnum):
    """Every event this pipeline can emit.

    An enum, not free strings: a mistyped event name produces telemetry that
    silently matches no query, which is worse than none because it looks like
    the operation never happened.
    """

    FETCH_STARTED = "fetch.started"
    FETCH_CACHE_HIT = "fetch.cache_hit"
    FETCH_RESUMED = "fetch.resumed"
    FETCH_RETRIED = "fetch.retried"
    FETCH_PUBLISHED = "fetch.published"
    FETCH_FAILED = "fetch.failed"

    EXTRACTION_STARTED = "extraction.started"
    EXTRACTION_CACHE_HIT = "extraction.cache_hit"
    EXTRACTION_AUTHORIZED = "extraction.authorized"
    EXTRACTION_DENIED = "extraction.denied"
    EXTRACTION_VERIFIED = "extraction.verified"
    EXTRACTION_PUBLISHED = "extraction.published"
    EXTRACTION_FAILED = "extraction.failed"

    # THE HANDOFF. Everything upstream is committed when this fires, so it
    # is the first moment a consumer may read the file. A consumer becomes
    # a reader of state rather than the owner of the side effect that
    # produced it.
    RAW_ARTIFACT_READY = "raw_artifact.ready"

    # The sequence failed as a whole. fetch and extract each report their
    # own failure, and neither tells a consumer waiting on the handoff why
    # it never arrived.
    ACQUISITION_FAILED = "acquisition.failed"


class Outcome(StrEnum):
    """Terminal disposition, so a query counts failures without parsing text."""

    SUCCESS = "success"
    FAILURE = "failure"


class PipelineEvent(BaseModel):
    """One observable moment, validated before it is emitted.

    Frozen and strict for the same reason the attestation records are: an event
    assembled from coerced input has numbers that cannot be trusted, and a
    dashboard built on untrustworthy numbers is worse than no dashboard.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: PipelineEventVersion = PIPELINE_EVENT_VERSION
    name: EventName
    occurred_at: UtcTimestamp

    # CORRELATION, on every event, so a query can reconstruct one run across
    # both ingestion phases and six machines.
    run_id: PathString
    actor: PathString

    # Subject. Nullable because not every event has every field: a denial has
    # no duration, a start has no digest. Fabricating them would be worse.
    member: str | None = None
    archive_sha256: str | None = None
    member_sha256: str | None = None

    # SECONDS, NOT MILLISECONDS, and the earlier comment here was simply wrong
    # about the convention. OpenTelemetry states that instruments measuring
    # durations SHOULD use seconds, and it deliberately migrated
    # http.server.duration (ms) to http.server.request.duration (s) to align
    # with Prometheus and OpenMetrics, which strongly recommend seconds. A
    # millisecond field forces a /1e3 into every query that joins this data to
    # anything else.
    #
    # The unit lives in the field DESCRIPTION rather than the name, matching how
    # the spec carries it, and the name stays `duration` so it maps onto a
    # duration histogram without renaming later.
    duration: float | None = Field(
        default=None, ge=0, description="Service time in seconds, excluding queue wait"
    )

    # QUEUE TIME, SEPARATE FROM SERVICE TIME. Reporting only one is wrong in
    # either direction: folding the wait into `duration` makes a contended run
    # look like a slow disk, while discarding it makes lock contention
    # invisible -- and ignored queueing is a documented way to hide a root
    # cause, because serialization bottlenecks appear in no single service's
    # latency number.
    #
    # Six agents contend for the same artifact here, so this is the field that
    # separates "the network was slow" from "five agents were ahead of us".
    queue_duration: float | None = Field(
        default=None, ge=0, description="Seconds spent waiting for the lock"
    )
    bytes_total: int | None = Field(default=None, ge=0)
    crc32: int | None = Field(default=None, ge=0, le=0xFFFFFFFF)

    # Why. policy_version answers "under which rules"; reason answers "why not".
    policy_version: str | None = None
    reason: str | None = None

    # SPEC ATTRIBUTES, emitted under their OpenTelemetry names via
    # serialization_alias. Python identifiers cannot contain dots, so the alias
    # is what puts url.full and error.type on the wire under the names every
    # OTel-aware backend already understands.
    #
    # Reusing a spec attribute beats inventing one: a backend that knows
    # error.type can group failures without a mapping layer, and a custom
    # error_kind would need translating in every query forever.
    url_full: str | None = Field(default=None, serialization_alias="url.full")
    error_type: str | None = Field(default=None, serialization_alias="error.type")

    # http.request.resend_count is the SPEC attribute for retries: "the ordinal
    # number of the request resend attempt". Absent on the first request, 1 on
    # the first resend. Inventing `attempt` here would have been the documented
    # mistake -- telemetry that cannot correlate with anything else.
    #
    # A 283MB transfer can resend four times with exponential backoff and
    # currently leaves no trace, so "why was this run slow" has no answer.
    resend_count: int | None = Field(
        default=None, ge=1, serialization_alias="http.request.resend_count"
    )

    # Custom, and namespaced separately on purpose: putting our own meaning
    # under http.* would blur spec-defined and locally-invented attributes.
    resumed_from_bytes: int | None = Field(default=None, ge=0)
    source: str | None = None

    # WHERE THE COMMITTED BYTES ARE. Carried on the handoff event so a
    # consumer never reconstructs the path itself and drifts from what was
    # actually written.
    uri: str | None = None

    outcome: Outcome | None = None


def event(name: EventName, **fields: object) -> PipelineEvent:
    """Build an event with the run context already attached.

    Correlation is filled here rather than at each call site: an event missing
    run_id cannot be joined to anything, and asking thirty call sites to
    remember is exactly how that happens.
    """
    run = current_run()
    return PipelineEvent.model_validate(
        {
            "name": name,
            "occurred_at": datetime.now(UTC),
            "run_id": run.run_id,
            "actor": run.actor,
            **fields,
        }
    )


def emit(pipeline_event: PipelineEvent) -> None:
    """Publish one already-validated event.

    Takes a constructed model rather than keyword arguments, so validation has
    happened at the call site and this function cannot be handed something
    malformed.

    exclude_none keeps absent fields out of the payload entirely: a log store
    charges for nulls, and "field absent" and "field null" mean the same thing
    here.
    """
    _LOGGER.info(
        "%s member=%s",
        pipeline_event.name.value,
        pipeline_event.member or "-",
        extra={EVENT_KEY: pipeline_event.model_dump(mode="json", exclude_none=True, by_alias=True)},
    )


@contextmanager
def timed() -> Iterator[dict[str, float]]:
    """Measure a block and expose elapsed SECONDS in the yielded dict.

    perf_counter, not time(): a wall clock can step backwards across an NTP
    adjustment and yield a negative duration, which the model would then reject
    at the worst possible moment. The dict is filled in a finally block, so a
    failing operation still reports how long it ran before it failed.
    """
    started = time.perf_counter()
    holder: dict[str, float] = {}
    try:
        yield holder
    finally:
        holder["duration"] = time.perf_counter() - started
