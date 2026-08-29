# tests/test_fetch_concurrency.py
"""Concurrency safety for fetching.

fetch.py cannot use a unique staging name: resuming a 283MB download requires
the partial to keep the SAME name across process restarts. A stable name is
shared by every invocation, so the lock is the entire defence here rather than
one of two layers.

The failure it prevents is nastier than extraction's. Two agents appending to
one partial interleave their bytes into a single file that is the right length
and wrong content, and sha256 only catches that after the whole transfer has
been paid for.

Threads, not subprocesses: flock associates the lock with the open file
description, so two separate opens conflict even inside one interpreter, and
pytest-httpx can only patch transport in-process.
"""

from __future__ import annotations

import hashlib
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path

import httpx
import pytest

from spark_batch_pipeline.atomicio import STAGING_SUFFIX, exclusive_lock, staging_path
from spark_batch_pipeline.ingest.fetch import IngestManifest, fetch_source

PAYLOAD = b"col_a,col_b\n1,2\n3,4\n" * 5_000
PAYLOAD_SHA = hashlib.sha256(PAYLOAD).hexdigest()
URL = "https://databank.example.org/data/download/WDI_CSV.zip"
WORKERS = 4


class _SlowTransport(httpx.BaseTransport):
    """Serves the payload slowly enough that workers genuinely overlap.

    A transport that returns instantly would let each worker finish before the
    next starts, and the test would pass whether or not the lock exists.
    """

    def __init__(self, delay: float = 0.05) -> None:
        self.delay = delay
        self.requests = 0
        self._guard = threading.Lock()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        with self._guard:
            self.requests += 1
        time.sleep(self.delay)
        return httpx.Response(200, content=PAYLOAD)


def _fetch(dest: Path, transport: _SlowTransport) -> IngestManifest:
    with httpx.Client(transport=transport, follow_redirects=True) as client:
        return fetch_source(source_name="wdi", url=URL, dest_dir=dest, client=client)


def test_concurrent_fetches_produce_one_correct_artifact(tmp_path: Path) -> None:
    transport = _SlowTransport()

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        manifests = list(pool.map(lambda _: _fetch(tmp_path, transport), range(WORKERS)))

    assert {m.sha256 for m in manifests} == {PAYLOAD_SHA}
    assert (tmp_path / "WDI_CSV.zip").read_bytes() == PAYLOAD


def test_concurrent_fetches_do_not_interleave_bytes(tmp_path: Path) -> None:
    """The specific corruption a shared appendable partial produces."""
    transport = _SlowTransport()

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        list(pool.map(lambda _: _fetch(tmp_path, transport), range(WORKERS)))

    artifact = tmp_path / "WDI_CSV.zip"
    assert artifact.stat().st_size == len(PAYLOAD), "size suggests appended duplicates"
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == PAYLOAD_SHA


def test_the_lock_prevents_redundant_downloads(tmp_path: Path) -> None:
    """Serialising is not only about safety: the later workers find the fetch
    already complete and skip 283MB of transfer entirely."""
    transport = _SlowTransport()

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        list(pool.map(lambda _: _fetch(tmp_path, transport), range(WORKERS)))

    assert transport.requests == 1, (
        f"{transport.requests} transfers for {WORKERS} workers; the lock should "
        "let the first finish and the rest observe a completed fetch"
    )


def test_no_staging_files_survive_concurrent_fetches(tmp_path: Path) -> None:
    transport = _SlowTransport()

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        list(pool.map(lambda _: _fetch(tmp_path, transport), range(WORKERS)))

    leftovers = list(tmp_path.glob(f"*{STAGING_SUFFIX}"))
    assert leftovers == [], f"staging garbage survived: {leftovers}"


def test_manifest_is_valid_after_concurrent_fetches(tmp_path: Path) -> None:
    transport = _SlowTransport()

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        list(pool.map(lambda _: _fetch(tmp_path, transport), range(WORKERS)))

    record = IngestManifest.model_validate_json(
        IngestManifest.path_for(tmp_path / "WDI_CSV.zip").read_text()
    )
    assert record.sha256 == PAYLOAD_SHA
    assert record.size_bytes == len(PAYLOAD)


def test_fetch_waits_for_a_held_lock(tmp_path: Path) -> None:
    """A fetch must block rather than proceed while another holds the lock."""
    artifact = tmp_path / "WDI_CSV.zip"
    transport = _SlowTransport(delay=0.0)

    with ExitStack() as stack:
        stack.enter_context(exclusive_lock(artifact))

        with pytest.raises(TimeoutError, match="another process"):
            stack.enter_context(exclusive_lock(artifact, timeout=0.3))

    # Once released, a normal fetch proceeds.
    manifest = _fetch(tmp_path, transport)
    assert manifest.sha256 == PAYLOAD_SHA


def test_resume_still_uses_a_stable_staging_name(tmp_path: Path) -> None:
    """Guards the design decision: uniquifying this name would silently break
    resumption of an interrupted 283MB transfer."""
    artifact = tmp_path / "WDI_CSV.zip"

    assert staging_path(artifact).name == f"WDI_CSV.zip{STAGING_SUFFIX}"
    assert staging_path(artifact) == staging_path(artifact)
