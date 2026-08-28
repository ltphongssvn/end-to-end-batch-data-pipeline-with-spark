# tests/test_probe.py
"""Probe contract tests.

The result type IS the published interface, so these defend it as one. Field
names, types, and constraints are pinned by the committed JSON Schema and
verified by `mise run check:contracts`; these tests cover what a schema file
cannot -- parsing behaviour, the cross-field invariants, and the CLI stream and
exit-code contract that an agent branches on before parsing anything.

Fixtures build a synthetic zip, so nothing here needs the real 283 MB archive.
"""

from __future__ import annotations

import csv
import io
import json
import zipfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from spark_batch_pipeline.ingest.probe import (
    SCHEMA_VERSION,
    ExitCode,
    WdiProbeResult,
    main,
    probe_wdi_archive,
)

FAKE_SHA = "a" * 64


def _write_archive(path: Path, headers: list[str], rows: list[list[str]]) -> Path:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(headers)
    writer.writerows(rows)
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("WDICSV.csv", buffer.getvalue())
    return path


def _headers(first: int = 1960, last: int = 1962) -> list[str]:
    return ["Country Name", "Country Code", "Indicator Name", "Indicator Code"] + [
        str(year) for year in range(first, last + 1)
    ]


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    rows = [["Aruba", "ABW", "Fertilizer", "AG.CON", "1", "2", "3"]] * 3
    return _write_archive(tmp_path / "WDI_CSV.zip", _headers(), rows)


# --- Parsing behaviour ------------------------------------------------------


def test_classifies_identifiers_and_years(archive: Path) -> None:
    result = probe_wdi_archive(archive, sha256=FAKE_SHA)
    assert result.identifier_headers == (
        "Country Name",
        "Country Code",
        "Indicator Name",
        "Indicator Code",
    )
    assert result.year_columns == (1960, 1961, 1962)
    assert result.total_columns == 7
    assert result.is_rectangular


def test_year_range_is_not_hardcoded(tmp_path: Path) -> None:
    """The PDF assumes 1960-2020; the live file already runs to 2025. Years must
    be derived from the header, never from a literal range."""
    path = _write_archive(tmp_path / "future.zip", _headers(1960, 2030), [["a"] * 75])
    result = probe_wdi_archive(path, sha256=FAKE_SHA)
    assert result.year_columns[-1] == 2030


def test_bom_is_stripped(tmp_path: Path) -> None:
    """The World Bank ships a byte order mark. Without utf-8-sig the first
    header keeps a leading U+FEFF and never matches 'Country Name'."""
    path = tmp_path / "bom.zip"
    body = "\ufeffCountry Name,Country Code,Indicator Name,Indicator Code,1960\nA,B,C,D,1\n"
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("WDICSV.csv", body)
    assert probe_wdi_archive(path, sha256=FAKE_SHA).identifier_headers[0] == "Country Name"


def test_trailing_empty_header_is_detected(tmp_path: Path) -> None:
    """A trailing comma is a classic WDI quirk; unhandled it becomes a phantom
    column that breaks the unpivot."""
    path = _write_archive(
        tmp_path / "trailing.zip",
        [*_headers(1960, 1961), ""],
        [["Aruba", "ABW", "Fertilizer", "AG.CON", "1", "2", ""]],
    )
    result = probe_wdi_archive(path, sha256=FAKE_SHA)
    assert result.trailing_empty_header
    assert result.total_columns == 7
    assert result.year_columns == (1960, 1961)


def test_ragged_rows_are_visible(tmp_path: Path) -> None:
    path = _write_archive(
        tmp_path / "ragged.zip", _headers(1960, 1961), [["a", "b", "c", "d", "1"]]
    )
    assert not probe_wdi_archive(path, sha256=FAKE_SHA).is_rectangular


# --- Invariants a JSON Schema cannot express --------------------------------


def test_unaccounted_column_is_rejected() -> None:
    """Every column must be classified. A column silently dropped would corrupt
    the unpivot, so the model refuses to construct."""
    with pytest.raises(ValidationError, match="column accounting mismatch"):
        WdiProbeResult.model_validate(
            {
                "source_path": "x.zip",
                "source_sha256": FAKE_SHA,
                "member": "WDICSV.csv",
                "total_columns": 9,
                "identifier_headers": ["a", "b"],
                "year_columns": [1960, 1961],
                "trailing_empty_header": False,
                "sample_row_widths": [9],
                "members": [],
                "probed_at": "2026-08-28T00:00:00Z",
            }
        )


def test_consumer_pinned_to_v1_rejects_a_bump() -> None:
    """A consumer pinned to v1 must fail loudly on v2, never misread it."""
    with pytest.raises(ValidationError) as caught:
        WdiProbeResult.model_validate({"schema_version": "wdi-probe/v2"})
    assert any(e["loc"] == ("schema_version",) for e in caught.value.errors())


def test_types_are_machine_friendly(archive: Path) -> None:
    """Numbers are numbers, not strings like '70 columns'."""
    payload = json.loads(probe_wdi_archive(archive, sha256=FAKE_SHA).model_dump_json())
    assert isinstance(payload["total_columns"], int)
    assert all(isinstance(year, int) for year in payload["year_columns"])
    assert isinstance(payload["trailing_empty_header"], bool)


# --- CLI stream and exit-code contract --------------------------------------


def test_json_mode_stdout_is_pure_json(archive: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """If --json cannot promise a clean stdout, it is not really a JSON mode."""
    code = main([str(archive), "--sha256", FAKE_SHA, "--json"])
    out, _ = capsys.readouterr()
    assert code == ExitCode.OK
    assert json.loads(out)["schema_version"] == SCHEMA_VERSION


def test_missing_archive_exits_not_found(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main([str(tmp_path / "absent.zip"), "--json"])
    out, err = capsys.readouterr()
    assert code == ExitCode.NOT_FOUND
    assert out == "", "stdout must stay parseable even on failure"
    assert "not found" in err


def test_missing_member_exits_not_found(archive: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main([str(archive), "--member", "NOPE.csv", "--sha256", FAKE_SHA, "--json"])
    out, err = capsys.readouterr()
    assert code == ExitCode.NOT_FOUND
    assert out == ""
    assert "NOPE.csv" in err


def test_human_mode_writes_nothing_to_stderr(
    archive: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main([str(archive), "--sha256", FAKE_SHA])
    out, err = capsys.readouterr()
    assert code == ExitCode.OK
    assert "columns" in out
    assert err == ""


def test_exit_codes_are_distinct() -> None:
    values = [code.value for code in ExitCode]
    assert len(values) == len(set(values))
    assert ExitCode.OK == 0
