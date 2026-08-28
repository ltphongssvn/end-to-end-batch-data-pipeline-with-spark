# src/spark_batch_pipeline/ingest/probe.py
"""Schema probe for the WDI archive, with a machine-readable output contract.

WHY A TYPED RESULT AND NOT PRINTED PROSE: a probe that only prints forces every
downstream consumer -- CI gates, agent loops, drift alarms -- to regex human
text. Field order, pluralization, or an added log line then silently breaks
them. The result type IS the interface; the human rendering is a view of it.

Pydantic is the right tool at exactly this scale: ONE probe result crossing a
process boundary, not millions of Spark rows. Validating per-record in a Spark
job would be a serious mistake; validating a single diagnostic object is what
turns "trust the stdout" into "the shape is guaranteed".

OUTPUT CONTRACT
  stdout  the result, and nothing else. In --json mode a single JSON object;
          otherwise an aligned human rendering of the same fields.
  stderr  every diagnostic, progress line, and error. If --json cannot promise
          a clean stdout it is not really a JSON mode.
  exit    0 success | 2 usage error | 3 source not found | 4 schema violation
          Agents branch on the exit code before parsing anything.

SCHEMA VERSIONING: schema_version is a Literal, so a consumer pinned to
wdi-probe/v1 fails loudly on a bump instead of misreading new fields. Additive
changes stay within v1; any rename or removal requires v2. A golden test pins
the exact field set so a breaking change cannot merge unnoticed.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
import zipfile
from datetime import UTC, datetime
from enum import IntEnum
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, NonNegativeInt, PositiveInt, model_validator

from spark_batch_pipeline.ingest.fetch import sha256_of

# The schema version is declared ONCE, as a named literal type. The alias is
# what a consumer imports to pin itself to v1, and typing the constant with it
# means the constant, the field, and any consumer annotation are the same type
# by construction rather than by three matching string copies.
type SchemaVersion = Literal["wdi-probe/v1"]
SCHEMA_VERSION: Final[SchemaVersion] = "wdi-probe/v1"
DEFAULT_MEMBER = "WDICSV.csv"
_SAMPLE_ROWS = 3


class ExitCode(IntEnum):
    """Documented exit contract. Agents branch on these before parsing stdout."""

    OK = 0
    FAILURE = 1
    USAGE = 2
    NOT_FOUND = 3
    SCHEMA_VIOLATION = 4


class ArchiveMember(BaseModel):
    """One file inside the WDI zip."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    filename: str = Field(min_length=1)
    size_bytes: NonNegativeInt


class WdiProbeResult(BaseModel):
    """Validated description of the WDI wide-format CSV schema.

    Deliberately flat and primitively typed: an agent reads year_columns[-1]
    without walking a nested tree, and every number is a number rather than a
    string like "70 columns".
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: SchemaVersion = SCHEMA_VERSION
    source_path: str
    source_sha256: str = Field(min_length=64, max_length=64)
    member: str
    total_columns: PositiveInt
    identifier_headers: tuple[str, ...]
    year_columns: tuple[int, ...]
    trailing_empty_header: bool
    sample_row_widths: tuple[PositiveInt, ...]
    members: tuple[ArchiveMember, ...]
    probed_at: datetime

    @model_validator(mode="after")
    def _columns_account_for_every_header(self) -> WdiProbeResult:
        """Every column must be classified. An unaccounted column means the
        source layout changed in a way this parser does not model, and silently
        dropping it would corrupt the unpivot downstream."""
        counted = (
            len(self.identifier_headers)
            + len(self.year_columns)
            + (1 if self.trailing_empty_header else 0)
        )
        if counted != self.total_columns:
            raise ValueError(
                f"column accounting mismatch: {counted} classified vs "
                f"{self.total_columns} present. The WDI layout changed."
            )
        return self

    @model_validator(mode="after")
    def _years_are_ascending(self) -> WdiProbeResult:
        years = list(self.year_columns)
        if years != sorted(years):
            raise ValueError("year columns are not in ascending order")
        return self

    @property
    def is_rectangular(self) -> bool:
        """False means ragged rows: the CSV cannot be trusted to a fixed schema."""
        return all(w == self.total_columns for w in self.sample_row_widths)


def probe_wdi_archive(
    archive: Path, member: str = DEFAULT_MEMBER, *, sha256: str | None = None
) -> WdiProbeResult:
    """Inspect the wide-format WDI member without decompressing it fully.

    Only the header and a few rows are read, so this stays cheap even though
    WDICSV.csv is ~198 MB uncompressed. Pass `sha256` to reuse a digest already
    computed by the ingest manifest instead of re-hashing 283 MB.
    """
    with zipfile.ZipFile(archive) as bundle:
        members = tuple(
            ArchiveMember(filename=info.filename, size_bytes=info.file_size)
            for info in bundle.infolist()
        )
        with bundle.open(member) as handle:
            # utf-8-sig strips the byte order mark the World Bank ships.
            # Without it the first header keeps a leading U+FEFF and no longer
            # compares equal to the plain header name, so every identifier
            # column silently fails to match.
            text = io.TextIOWrapper(handle, encoding="utf-8-sig", newline="")
            reader = csv.reader(text)
            headers = next(reader)
            widths = tuple(len(row) for _, row in zip(range(_SAMPLE_ROWS), reader, strict=False))

    trailing_empty = bool(headers) and headers[-1].strip() == ""
    classifiable = headers[:-1] if trailing_empty else headers

    years = tuple(int(h) for h in classifiable if h.strip().isdigit())
    identifiers = tuple(h for h in classifiable if not h.strip().isdigit())

    return WdiProbeResult(
        source_path=str(archive),
        source_sha256=sha256 or sha256_of(archive),
        member=member,
        total_columns=len(headers),
        identifier_headers=identifiers,
        year_columns=years,
        trailing_empty_header=trailing_empty,
        sample_row_widths=widths,
        members=members,
        probed_at=datetime.now(UTC),
    )


def _render_human(result: WdiProbeResult) -> str:
    lines = [
        f"source      {result.source_path}",
        f"sha256      {result.source_sha256}",
        f"member      {result.member}",
        f"columns     {result.total_columns}",
        f"identifiers {len(result.identifier_headers)}: {', '.join(result.identifier_headers)}",
        f"years       {len(result.year_columns)}: "
        f"{result.year_columns[0]}-{result.year_columns[-1]}"
        if result.year_columns
        else "years       none",
        f"trailing empty header: {result.trailing_empty_header}",
        f"rectangular {result.is_rectangular} (sample widths {list(result.sample_row_widths)})",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="probe-wdi", description="Probe the WDI archive schema.")
    parser.add_argument("archive", type=Path, help="Path to WDI_CSV.zip")
    parser.add_argument("--member", default=DEFAULT_MEMBER)
    parser.add_argument("--sha256", default=None, help="Reuse a known digest")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON on stdout")
    args = parser.parse_args(argv)

    if not args.archive.is_file():
        # Diagnostics go to stderr so stdout stays parseable even on failure.
        print(f"archive not found: {args.archive}", file=sys.stderr)
        return ExitCode.NOT_FOUND

    try:
        result = probe_wdi_archive(args.archive, args.member, sha256=args.sha256)
    except KeyError:
        print(f"member not found in archive: {args.member}", file=sys.stderr)
        return ExitCode.NOT_FOUND
    except ValueError as exc:
        print(f"schema violation: {exc}", file=sys.stderr)
        return ExitCode.SCHEMA_VIOLATION

    if args.as_json:
        # sort_keys makes the bytes stable, so a golden test diffs meaningfully.
        print(json.dumps(json.loads(result.model_dump_json()), sort_keys=True))
    else:
        print(_render_human(result))
    return ExitCode.OK


if __name__ == "__main__":
    raise SystemExit(main())
