# tests/test_extract_concurrency.py
"""Concurrency safety for extraction.

Idempotent-under-sequential-execution and safe-under-concurrency are different
properties. Everything before this file tested the first. These test the second:
real processes, a real shared target, and a real kernel lock.

Subprocesses rather than threads on purpose. flock is a per-descriptor kernel
lock, and the failure being guarded against is two OS processes -- two agents,
two CI jobs -- not two threads in one interpreter. Threads would exercise the
GIL, not the lock.
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path

import pytest

from spark_batch_pipeline.atomicio import STAGING_SUFFIX, exclusive_lock, lock_path
from spark_batch_pipeline.ingest.extract import (
    ExtractionRecord,
    ExtractionState,
    inspect_extraction,
)

# Large enough that extraction is not instantaneous, so the workers genuinely
# overlap rather than finishing one after another by luck.
BODY = b"Country Name,Country Code,1960\nAruba,ABW,1.5\n" * 60_000
MEMBER = "WDICSV.csv"

_WORKER = """
import sys
from pathlib import Path
from spark_batch_pipeline.ingest.extract import extract_member

record = extract_member(Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]))
print(record.crc32)
"""


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    path = tmp_path / "WDI_CSV.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(MEMBER, BODY)
    return path


@pytest.fixture
def worker(tmp_path: Path) -> Path:
    script = tmp_path / "worker.py"
    script.write_text(_WORKER)
    return script


def _run(worker: Path, archive: Path, dest: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(worker), str(archive), MEMBER, str(dest)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_concurrent_processes_produce_one_correct_artifact(
    archive: Path, tmp_path: Path, worker: Path
) -> None:
    """The defect this guards: two agents sharing a fixed staging name both
    truncate it, and one publishes the other's half-written bytes."""
    dest = tmp_path / "raw"
    dest.mkdir()

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: _run(worker, archive, dest), range(4)))

    for result in results:
        assert result.returncode == 0, f"worker failed:\n{result.stderr}"

    crcs = {line.strip() for r in results for line in r.stdout.splitlines() if line.strip()}
    assert len(crcs) == 1, f"workers disagreed on the CRC: {crcs}"
    assert (dest / MEMBER).read_bytes() == BODY
    assert inspect_extraction(archive, MEMBER, dest).state is ExtractionState.COMMITTED


def test_no_staging_files_survive_concurrent_runs(
    archive: Path, tmp_path: Path, worker: Path
) -> None:
    dest = tmp_path / "raw"
    dest.mkdir()

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: _run(worker, archive, dest), range(4)))

    leftovers = list(dest.glob(f"*{STAGING_SUFFIX}"))
    assert leftovers == [], f"staging garbage survived: {leftovers}"


def test_sidecar_is_valid_after_concurrent_runs(
    archive: Path, tmp_path: Path, worker: Path
) -> None:
    """Racing sidecar writes must still leave exactly one parseable record."""
    dest = tmp_path / "raw"
    dest.mkdir()

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: _run(worker, archive, dest), range(4)))

    record = ExtractionRecord.model_validate_json(
        ExtractionRecord.path_for(dest / MEMBER).read_text()
    )
    assert record.size_bytes == len(BODY)


def test_staging_names_are_unique_per_run(archive: Path, tmp_path: Path) -> None:
    """mkstemp relies on O_EXCL, so two runs cannot receive the same path even
    if the lock were somehow bypassed."""
    from spark_batch_pipeline.atomicio import new_staging_path

    target = tmp_path / MEMBER
    names = {new_staging_path(target) for _ in range(50)}

    assert len(names) == 50
    assert all(n.parent == target.parent for n in names), "must stay same-filesystem"


def test_lock_is_exclusive(tmp_path: Path) -> None:
    """A second holder must be refused while the first still owns the lock.

    ExitStack rather than nested `with` blocks. Two nested statements trip
    SIM117; merging them is worse than a style problem, because contexts are
    entered left to right and the TimeoutError would be raised while ENTERING,
    before pytest.raises was guarding anything; and the callable form of
    pytest.raises trips PT010. enter_context is a plain call, so no rule
    applies and the first lock is still released if the assertion fails.

    Same process, two descriptors: flock associates the lock with the open file
    description, so two separate opens conflict even in one interpreter.
    """
    target = tmp_path / MEMBER

    with ExitStack() as stack:
        stack.enter_context(exclusive_lock(target))

        with pytest.raises(TimeoutError, match="another process"):
            stack.enter_context(exclusive_lock(target, timeout=0.5))


def test_lock_is_released_after_the_block(tmp_path: Path) -> None:
    target = tmp_path / MEMBER

    with exclusive_lock(target, timeout=1.0):
        pass

    with exclusive_lock(target, timeout=1.0):
        pass  # must not time out


def test_lock_file_lives_beside_its_target(tmp_path: Path) -> None:
    """Unlinking the lock would let two holders coexist on different inodes, so
    it is deliberately left behind."""
    target = tmp_path / MEMBER

    with exclusive_lock(target):
        pass

    assert lock_path(target).exists()
    assert lock_path(target).parent == target.parent
