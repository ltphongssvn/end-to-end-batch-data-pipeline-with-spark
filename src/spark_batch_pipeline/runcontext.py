# src/spark_batch_pipeline/runcontext.py
"""Who ran this, in which run, on which attempt.

WHAT THE SIDECARS ALREADY ANSWER: "what file did these bytes come from, and are
they intact?" The digest chain covers that -- archive_sha256 links an extraction
to the exact archive that caused it, which IS the causation edge, recorded as a
content digest rather than an opaque id.

WHAT THEY DID NOT ANSWER: "which orchestrated run produced this, and by which
actor?" With six laptops running autonomous agents against one repository, an
artifact that cannot name its run cannot be traced back to a decision.

IDS ARE W3C TRACE CONTEXT SHAPED, DELIBERATELY.
run_id is 32 lowercase hex characters -- exactly a W3C trace-id -- and step ids
are 16, exactly a span-id. Nothing here depends on OpenTelemetry: adding an SDK,
collector and exporters for a single-process batch job would be machinery for
identifiers we can mint in one line. But hand-rolled ID FORMATS are where
correlation breaks, so the format is borrowed even though the tooling is not.
Adopt OTel later and these fields accept a real trace_id unchanged -- a rename,
not a redesign.

WHY A MODULE-LEVEL CONSTANT AND NOT lru_cache.
The obvious spelling is @lru_cache on a factory, and it is subtly wrong here.
lru_cache is thread-safe against corruption but is NOT an
initialise-exactly-once contract: two threads calling before the value is cached
can each build a distinct object. For a run id that is precisely the bug the
field exists to prevent -- two artifacts from ONE invocation carrying two
different run ids, so grouping fails exactly when concurrency makes it matter.
This project's own tests drive extraction through a ThreadPoolExecutor.

Module-level initialisation is race-free: the import system guarantees a module
body executes once per process. Cost is a few microseconds of token_hex.

WHY NOT contextvars: those hold state that VARIES per execution context, which
is the opposite of what a run identity is. A run id must be identical across
every task in the process, so context-local storage would be the wrong shape.

ENVIRONMENT OVERRIDES let an orchestrator impose ITS run id. When Airflow, a
GitHub Actions job, or a supervising agent already owns a correlation id,
minting a local one fragments the trace at the boundary where it matters most.
Read at import, so they must be set before the process starts.
"""

from __future__ import annotations

import os
import platform
import secrets
from typing import Final

from pydantic import BaseModel, ConfigDict

from spark_batch_pipeline.valuetypes import PathString

# W3C Trace Context sizes: trace-id is 16 bytes as 32 hex chars, span-id 8 as 16.
_TRACE_ID_BYTES: Final = 16
_SPAN_ID_BYTES: Final = 8

RUN_ID_ENV: Final = "PIPELINE_RUN_ID"
ACTOR_ENV: Final = "PIPELINE_ACTOR"


def new_run_id() -> str:
    """A fresh W3C trace-id: 32 lowercase hex characters."""
    return secrets.token_hex(_TRACE_ID_BYTES)


def new_step_id() -> str:
    """A fresh W3C span-id: 16 lowercase hex characters."""
    return secrets.token_hex(_SPAN_ID_BYTES)


def _resolve_actor() -> str:
    """Who is running this, in a form a human can act on.

    An explicit override wins, then CI identity, then the machine. With six
    laptops the hostname is the difference between "an agent did this" and
    "the agent on THAT machine did this".
    """
    if explicit := os.environ.get(ACTOR_ENV):
        return explicit

    workflow = os.environ.get("GITHUB_WORKFLOW")
    run_number = os.environ.get("GITHUB_RUN_ID")
    if workflow and run_number:
        return f"github-actions:{workflow}#{run_number}"

    return f"host:{platform.node()}"


class RunContext(BaseModel):
    """Identity of one pipeline invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    run_id: PathString
    actor: PathString


# Resolved once, at import, for the life of the process. See the module
# docstring for why this is a module constant rather than a cached factory.
_CURRENT: Final = RunContext(
    run_id=os.environ.get(RUN_ID_ENV) or new_run_id(),
    actor=_resolve_actor(),
)


def current_run() -> RunContext:
    """The run context for this process.

    A function rather than exporting the constant directly, so tests can
    monkeypatch one name and callers never hold a stale reference.
    """
    return _CURRENT
