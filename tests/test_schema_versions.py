# tests/test_schema_versions.py
"""Versioned ingestion contracts.

A sidecar outlives the code that wrote it. Without a version, a future reader
cannot tell whether a missing field means "v1, which never had it" or "v2,
corrupted" -- so it either fails outright or, worse, silently misinterprets the
data. Kubernetes carries apiVersion in every manifest for the same reason.

Two properties are asserted here and neither is evident from reading the models:
that pre-versioning sidecars still parse (the default is what makes this change
backward compatible), and that a sidecar from a NEWER writer is refused rather
than misread.

RECORDS ARE PARSED FROM JSON, NOT FROM A DICT. Under strict mode Pydantic is
lenient only for JSON input, because JSON has no date type and so a string is
the only possible representation; passing that same string inside a Python dict
is correctly rejected. Pydantic's own guidance for non-JSON sources wanting
JSON-mode behaviour is to json.dumps the data first, which is what these tests
do -- and it mirrors production, where sidecars are always read with
model_validate_json. A dict-based fixture would exercise a path the pipeline
never takes.

PATHS ARE ANCHORED TO THIS FILE, not to the working directory. A bare
Path("contracts") resolves against CWD, so the same test would pass from the
repo root and fail when pytest runs from tests/ or from a git hook.
"""

from __future__ import annotations

import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from spark_batch_pipeline.ingest.extract import (
    EXTRACT_RECORD_VERSION,
    ExtractionRecord,
    ExtractionState,
    extract_member,
    inspect_extraction,
)
from spark_batch_pipeline.ingest.fetch import INGEST_MANIFEST_VERSION, IngestManifest

CONTRACTS_DIR = Path(__file__).resolve().parents[1] / "contracts"

BODY = b"Country Name,Country Code,1960\nAruba,ABW,1.5\n" * 40
MEMBER = "WDICSV.csv"


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    path = tmp_path / "WDI_CSV.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(MEMBER, BODY)
    return path


def _manifest_json(**overrides: object) -> str:
    """A manifest as it exists on disk: JSON, exactly as production reads it."""
    base: dict[str, object] = {
        "source_name": "wdi",
        "url": "https://example.org/WDI_CSV.zip",
        "filename": "WDI_CSV.zip",
        "size_bytes": 100,
        "sha256": "a" * 64,
        "ingested_at": datetime.now(UTC).isoformat(),
    }
    return json.dumps(base | overrides)


def _record_json(**overrides: object) -> str:
    base: dict[str, object] = {
        "archive": "x.zip",
        "member": MEMBER,
        "size_bytes": 1,
        "sha256": "a" * 64,
        "archive_sha256": "b" * 64,
        "crc32": 1,
        "extracted_at": datetime.now(UTC).isoformat(),
    }
    return json.dumps(base | overrides)


# --- The version travels with the document ----------------------------------


def test_extraction_record_carries_its_version(archive: Path, tmp_path: Path) -> None:
    dest = tmp_path / "raw"
    record = extract_member(archive, MEMBER, dest)

    assert record.schema_version == EXTRACT_RECORD_VERSION

    on_disk = json.loads(ExtractionRecord.path_for(dest / MEMBER).read_text())
    assert on_disk["schema_version"] == "extract-record/v1", (
        "the version must travel inside the document, not only in a filename"
    )


def test_manifest_carries_its_version() -> None:
    manifest = IngestManifest.model_validate_json(_manifest_json())

    assert manifest.schema_version == INGEST_MANIFEST_VERSION
    assert json.loads(manifest.model_dump_json())["schema_version"] == "ingest-manifest/v1"


# --- Backward compatibility: the reason the field is defaulted --------------


def test_pre_versioning_sidecar_still_parses(archive: Path, tmp_path: Path) -> None:
    """Sidecars written before schema_version existed have exactly the v1 field
    set, so reading them as v1 is accurate.

    Requiring the field would make every existing sidecar unparseable. That is
    SAFE -- the orphan model redoes the step -- but it would re-download 283MB
    and re-extract 198MB to recover a version string describing a shape that
    already matches.
    """
    dest = tmp_path / "raw"
    extract_member(archive, MEMBER, dest)
    record_file = ExtractionRecord.path_for(dest / MEMBER)

    legacy = json.loads(record_file.read_text())
    del legacy["schema_version"]
    record_file.write_text(json.dumps(legacy, indent=2))

    # COMMITTED: the sidecar is read, trusted, and no work is redone.
    assert inspect_extraction(archive, MEMBER, dest).state is ExtractionState.COMMITTED


def test_pre_versioning_manifest_still_parses() -> None:
    payload = _manifest_json()
    assert "schema_version" not in json.loads(payload)

    parsed = IngestManifest.model_validate_json(payload)
    assert parsed.schema_version == INGEST_MANIFEST_VERSION


# --- Forward incompatibility: refuse rather than misread --------------------


@pytest.mark.parametrize(
    "version", ["extract-record/v2", "extract-record/v0", "something-else", ""]
)
def test_unknown_extract_version_is_refused(version: str) -> None:
    """A record from a NEWER writer must not be silently misread.

    Deliberately not a tolerant reader. Ignoring unknown fields suits long-lived
    consumers evolving independently of producers; here the reader IS the
    writer, and the artifact is an attestation. Trusting a claim we cannot
    interpret is worse than repeating cheap work.
    """
    with pytest.raises(ValidationError) as caught:
        ExtractionRecord.model_validate_json(_record_json(schema_version=version))

    assert any(e["loc"] == ("schema_version",) for e in caught.value.errors())


def test_unknown_manifest_version_is_refused() -> None:
    with pytest.raises(ValidationError) as caught:
        IngestManifest.model_validate_json(_manifest_json(schema_version="ingest-manifest/v2"))

    assert any(e["loc"] == ("schema_version",) for e in caught.value.errors())


def test_future_sidecar_is_treated_as_unreadable(archive: Path, tmp_path: Path) -> None:
    """End to end: a sidecar from a newer writer resolves to ORPHANED, so the
    step is redone rather than the claim being trusted."""
    dest = tmp_path / "raw"
    extract_member(archive, MEMBER, dest)
    record_file = ExtractionRecord.path_for(dest / MEMBER)

    future = json.loads(record_file.read_text())
    future["schema_version"] = "extract-record/v99"
    record_file.write_text(json.dumps(future, indent=2))

    assert inspect_extraction(archive, MEMBER, dest).state is ExtractionState.ORPHANED


# --- The published contracts ------------------------------------------------


@pytest.mark.parametrize(
    ("filename", "version"),
    [
        ("extract-record-v1.schema.json", "extract-record/v1"),
        ("ingest-manifest-v1.schema.json", "ingest-manifest/v1"),
    ],
)
def test_published_contract_pins_the_version(filename: str, version: str) -> None:
    """An external consumer pins to the const in the published schema."""
    schema = json.loads((CONTRACTS_DIR / filename).read_text())
    consts = [definition.get("const") for definition in schema.get("$defs", {}).values()]

    assert version in consts, f"{filename} does not pin {version}"


def test_contract_filenames_derive_from_versions() -> None:
    """v2 must land BESIDE v1, never overwrite it: a published schema is
    immutable, and the directory is the history a future reader needs."""
    names = {path.name for path in CONTRACTS_DIR.glob("*.schema.json")}

    assert f"{EXTRACT_RECORD_VERSION.replace('/', '-')}.schema.json" in names
    assert f"{INGEST_MANIFEST_VERSION.replace('/', '-')}.schema.json" in names
