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

from spark_batch_pipeline.ingest.probe import SCHEMA_VERSION, WdiProbeResult

CONTRACTS_DIR: Final = Path(__file__).resolve().parents[2] / "contracts"

CONTRACTS: Final[dict[str, type[BaseModel]]] = {
    f"{SCHEMA_VERSION.replace('/', '-')}.schema.json": WdiProbeResult,
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
