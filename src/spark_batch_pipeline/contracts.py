# src/spark_batch_pipeline/contracts.py
"""Generate the committed JSON Schema contracts.

WHY A COMMITTED SCHEMA FILE RATHER THAN AN IN-TEST ASSERTION: a hand-written
`set(payload) == {...}` captures field NAMES only, so a type change, a loosened
constraint, or a new enum value passes silently. It is also a second
hand-maintained copy of the model -- the duplication this project removes
everywhere else.

The generated schema captures names, types, and constraints together. Committed
to git it becomes a reviewable diff, so a contract change is something a
reviewer actually sees in the PR, and it doubles as the artifact an external
consumer pins against.

WHY NOT SYRUPY: an .ambr snapshot is test-only. This file is both the published
contract and the regression guard, so one artifact serves both roles.

Normalization is what makes the diff meaningful: sorted keys and a fixed indent,
so reordering inside Pydantic cannot masquerade as a contract change.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

from pydantic import BaseModel

from spark_batch_pipeline.ingest.acquire import (
    RAW_ARTIFACT_VERSION,
    RawArtifact,
)
from spark_batch_pipeline.ingest.extract import (
    EXTRACT_RECORD_VERSION,
    ExtractionRecord,
)
from spark_batch_pipeline.ingest.fetch import INGEST_MANIFEST_VERSION, IngestManifest
from spark_batch_pipeline.ingest.probe import SCHEMA_VERSION, WdiProbeResult
from spark_batch_pipeline.telemetry import PIPELINE_EVENT_VERSION, PipelineEvent

CONTRACTS_DIR: Final = Path(__file__).resolve().parents[2] / "contracts"

# Every artifact that crosses a process boundary and carries a schema_version.
#
# THE FILENAME IS DERIVED FROM THE VERSION STRING, deliberately. A published
# schema is immutable: when v2 arrives its file lands BESIDE v1 instead of
# overwriting it, so the directory becomes a readable history of every shape
# this pipeline has written -- which is precisely what someone holding an old
# sidecar needs in order to interpret it.
#
# The version also travels inside each document, not only in the filename. A
# file can be renamed, copied, or read from a stream where the name is gone;
# the schema_version field cannot be separated from the data it describes.
#
# WHAT BUMPS A VERSION: renaming a field, removing one, narrowing a type, or
# changing the meaning of an existing default. Adding an optional field WITH a
# default stays v1, which is the standard backward-compatible change -- old
# records simply take the default, exactly as Avro and Protobuf treat it. Either
# way check:contracts turns the change into a reviewable diff.
CONTRACTS: Final[dict[str, type[BaseModel]]] = {
    f"{SCHEMA_VERSION.replace('/', '-')}.schema.json": WdiProbeResult,
    f"{INGEST_MANIFEST_VERSION.replace('/', '-')}.schema.json": IngestManifest,
    f"{EXTRACT_RECORD_VERSION.replace('/', '-')}.schema.json": ExtractionRecord,
    # THE HANDOFF, and publishing it is a deliberate declaration rather than
    # a reflex. The consumer is a Dagster asset in a SEPARATE environment
    # with its own lockfile -- it cannot import this package, so the JSON
    # Schema is the only thing it can consume. Services share a schema and
    # contract, not a class.
    #
    # No separate DTO: the model IS the wire shape, and a parallel struct
    # with no divergence to justify it would be duplication. If the internal
    # model ever needs a shape the wire cannot follow, that is the moment to
    # split them -- not before.
    f"{RAW_ARTIFACT_VERSION.replace('/', '-')}.schema.json": RawArtifact,
    # Telemetry is a contract like any other: an event whose shape drifts
    # breaks every query and dashboard built on it, silently.
    f"{PIPELINE_EVENT_VERSION.replace('/', '-')}.schema.json": PipelineEvent,
}


def render(model: type[BaseModel]) -> str:
    """Serialize a model's JSON Schema deterministically."""
    return json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n"


def write_all(directory: Path = CONTRACTS_DIR) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    return [
        (directory / filename, (directory / filename).write_text(render(model)))[0]
        for filename, model in CONTRACTS.items()
    ]


def main() -> int:
    for path in write_all():
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
