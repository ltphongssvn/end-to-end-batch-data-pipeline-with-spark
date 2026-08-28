# tests/test_fetch.py
"""Raw-layer fetch tests. No network: pytest-httpx patches the transport.

Deliberately NO client injection. fetch_source builds its own httpx.Client when
none is passed, and that construction carries the timeout and redirect policy.
Handing in a client configured by the test would mean the test asserts its own
settings -- a redirect test that sets follow_redirects itself passes even when
production forgets it, which is precisely the silent failure being guarded.

Each test encodes a failure that costs something real: re-transferring 283 MB,
storing a redirect stub as if it were data, corrupting a resumed file, or
retrying a permanent error.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import httpx
import pytest
from pytest_httpx import HTTPXMock

from spark_batch_pipeline.ingest.fetch import IngestManifest, fetch_source, sha256_of

PAYLOAD = b"col_a,col_b\n1,2\n3,4\n" * 100
PAYLOAD_SHA = hashlib.sha256(PAYLOAD).hexdigest()

URL = "https://databank.example.org/data/download/WDI_CSV.zip"
REDIRECT_TARGET = "https://databankfiles.example.org/public/WDI_CSV.zip"


@pytest.fixture(autouse=True)
def _no_backoff_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Retry logic is under test; real backoff sleeps are not."""
    monkeypatch.setattr("spark_batch_pipeline.ingest.fetch._sleep_backoff", lambda _: None)


def test_fetch_writes_artifact_and_manifest(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    httpx_mock.add_response(
        content=PAYLOAD,
        headers={"ETag": '"abc123"', "Last-Modified": "Wed, 15 Jul 2026 02:19:16 GMT"},
    )

    manifest = fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)

    artifact = tmp_path / "WDI_CSV.zip"
    assert artifact.read_bytes() == PAYLOAD
    assert manifest.sha256 == PAYLOAD_SHA
    assert manifest.size_bytes == len(PAYLOAD)
    assert manifest.etag == '"abc123"'
    assert manifest.last_modified == "Wed, 15 Jul 2026 02:19:16 GMT"
    assert manifest.source_name == "wdi"
    assert IngestManifest.path_for(artifact).exists()


def test_second_fetch_makes_no_request(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    """The whole point. A re-run must not re-transfer the artifact.

    Only one response is registered: if the second call hit the network,
    pytest-httpx would fail with no matching response.
    """
    httpx_mock.add_response(content=PAYLOAD)

    first = fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)
    second = fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)

    assert len(httpx_mock.get_requests()) == 1
    assert first.sha256 == second.sha256


def test_corrupted_artifact_is_refetched(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    """A manifest asserting a digest the file no longer has must not be trusted."""
    httpx_mock.add_response(content=PAYLOAD, is_reusable=True)

    fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)
    (tmp_path / "WDI_CSV.zip").write_bytes(b"truncated")
    manifest = fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)

    assert len(httpx_mock.get_requests()) == 2
    assert manifest.sha256 == PAYLOAD_SHA


def test_redirect_is_followed(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    """databank.worldbank.org 301s to databankfiles.

    Without follow_redirects on the client fetch_source builds, this stores a
    193-byte HTML stub and reports success. Because no client is injected, this
    fails if that flag is ever dropped from production code.
    """
    httpx_mock.add_response(url=URL, status_code=301, headers={"Location": REDIRECT_TARGET})
    httpx_mock.add_response(url=REDIRECT_TARGET, content=PAYLOAD)

    manifest = fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)

    assert manifest.sha256 == PAYLOAD_SHA, "stored the redirect body, not the artifact"
    assert manifest.size_bytes == len(PAYLOAD)


def test_resume_appends_from_partial(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    """A 206 must append to .part rather than restart the transfer."""
    split = 500
    (tmp_path / "WDI_CSV.zip.part").write_bytes(PAYLOAD[:split])
    httpx_mock.add_response(status_code=206, content=PAYLOAD[split:])

    manifest = fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)

    sent = httpx_mock.get_requests()[0]
    assert sent.headers.get("Range") == f"bytes={split}-"
    assert manifest.sha256 == PAYLOAD_SHA


def test_server_ignoring_range_restarts_cleanly(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    """A 200 answering a Range request means the full body is coming.
    Appending it to the existing bytes would silently corrupt the artifact."""
    (tmp_path / "WDI_CSV.zip.part").write_bytes(PAYLOAD[:500])
    httpx_mock.add_response(status_code=200, content=PAYLOAD)

    manifest = fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)

    assert manifest.sha256 == PAYLOAD_SHA
    assert manifest.size_bytes == len(PAYLOAD)


def test_transient_503_is_retried(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    httpx_mock.add_response(status_code=503)
    httpx_mock.add_response(status_code=503)
    httpx_mock.add_response(content=PAYLOAD)

    manifest = fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)

    assert len(httpx_mock.get_requests()) == 3
    assert manifest.sha256 == PAYLOAD_SHA


def test_transport_error_is_retried(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    httpx_mock.add_exception(httpx.ReadTimeout("read timed out"))
    httpx_mock.add_response(content=PAYLOAD)

    manifest = fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)

    assert len(httpx_mock.get_requests()) == 2
    assert manifest.sha256 == PAYLOAD_SHA


def test_404_is_not_retried(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    """Retrying a 404 only delays the real message. This is exactly how the
    WDI_csv.zip -> WDI_CSV.zip rename surfaced."""
    httpx_mock.add_response(status_code=404)

    with pytest.raises(httpx.HTTPStatusError):
        fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)

    assert len(httpx_mock.get_requests()) == 1, "a 404 is config error, not transient"


def test_no_partial_survives_success(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    """Atomic publish: a reader must never see a half-written raw artifact."""
    httpx_mock.add_response(content=PAYLOAD)

    fetch_source(source_name="wdi", url=URL, dest_dir=tmp_path)

    assert not (tmp_path / "WDI_CSV.zip.part").exists()


def test_sha256_of_matches_hashlib(tmp_path: Path) -> None:
    target = tmp_path / "blob.bin"
    target.write_bytes(PAYLOAD)
    assert sha256_of(target) == PAYLOAD_SHA
