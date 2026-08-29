# src/spark_batch_pipeline/atomicio.py
"""The commit boundary for files written into the lakehouse.

WHY THIS MODULE EXISTS: fetch.py and extract.py each published a staged file
with shutil.move and wrote its sidecar with write_text. The same shape, written
twice, wrong in the same ways both times.

TWO GUARANTEES, OFTEN CONFLATED
  ATOMICITY  a reader sees the old file or the new one, never a partial. POSIX
             guarantees rename() is atomic with respect to other filesystem
             operations, which is what makes stage-then-rename work.
  DURABILITY the bytes survive sudden power loss. Renaming does NOT provide
             this: write() normally lands in the page cache, and on ext4 in
             ordered mode only metadata is journalled, so a name can become
             durable while the data it points at has not been written back.

A THIRD PROPERTY, AND IT IS NOT IMPLIED BY THE OTHER TWO
  EXCLUSION  two processes writing the same target do not corrupt each other.
Idempotent-under-sequential-execution and safe-under-concurrency are different
claims. A fixed staging name like "<target>.part" is shared by every invocation
targeting that file, so two agents both open it, both truncate it, and one
publishes the other's half-written bytes -- or renames a file the other still
holds open. CRC verification turns that into a confusing failure rather than
silent corruption, which is better but is not safety.

Both halves of the standard fix are provided:
  exclusive_lock()   kernel-enforced flock around check-and-commit, so only one
                     writer decides and publishes at a time
  new_staging_path() a per-run unique name from mkstemp, which has no race in
                     its creation because it relies on O_EXCL
Unique names alone would not suffice: two processes would still both do the
work and both publish, racing on the sidecar. The lock alone would suffice for
correctness, but unique names also stop a dead run's leftovers from being
mistaken for the current one.

STABLE VERSUS UNIQUE STAGING: fetch.py resumes an interrupted 283MB download,
which requires the partial to keep the SAME name across process restarts, so it
uses staging_path() guarded by the lock. extract.py cannot resume -- a zip
member cannot be inflated from an arbitrary offset -- so it uses a unique name
and treats leftovers as garbage.

WHY NOT shutil.move: it degrades to copy-then-delete across filesystems. That
fallback is not atomic and fails silently -- the code looks correct and the
guarantee is simply absent. Path.replace is the os.replace syscall: it either
performs a same-filesystem replace or raises.

THE PUBLISH SEQUENCE
  1. fsync the staged file      flush its contents and metadata
  2. Path.replace               atomically swap the name
  3. fsync the parent directory flush the directory entry itself
Step 3 is the one usually forgotten. Without it the CONTENTS can be durable
while the NAME reaching them is not, so a crash can revert the file to its old
name or lose it entirely.

TWO-PHASE COMMIT, AND WHY SIDECARS NEED THE SAME PROTOCOL
Data is published first, then its sidecar, matching how Iceberg commits: data
files are written, then a metadata pointer is swapped atomically, so a crash in
between leaves ORPHAN DATA -- present but referenced by nothing, therefore
invisible and safely redone. That model only holds if the sidecar write is
itself atomic. A half-written sidecar is worse than a missing one: missing means
"redo the step", truncated means the next run reads invalid JSON and fails.

macOS SPECIFICALLY: fsync on Darwin does not flush the drive's internal write
cache. F_FULLFSYNC does. This project is developed on macOS and runs on Linux in
CI, so both paths are handled rather than assuming one.

This does not defeat a lying disk. No POSIX API reaches a drive that
acknowledges writes it has not persisted; F_FULLFSYNC is as far as the OS goes.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

# Staging suffix shared by data and metadata, so a crashed run leaves an
# obviously-incomplete name in both cases.
STAGING_SUFFIX = ".part"
LOCK_SUFFIX = ".lock"

# Contention here means another agent is fetching or extracting the same
# artifact, which can legitimately take minutes on a 283MB download. Waiting is
# correct; waiting forever is not, so the bound is generous but finite.
DEFAULT_LOCK_TIMEOUT = 900.0
_LOCK_POLL_SECONDS = 0.25


def _full_fsync(fd: int) -> None:
    """Flush a file descriptor as far down the stack as the platform allows.

    The platform test is written INLINE as `sys.platform == "darwin"`, not via a
    module-level boolean. mypy narrows on sys.platform comparisons only inside
    if/elif/else statements, so an intermediate constant defeats it: the checker
    then analyses the Darwin branch on Linux and reports F_FULLFSYNC missing,
    which is a real CI failure that cannot reproduce on a Mac.

    Because narrowing works, mypy on Linux skips this branch entirely -- so the
    branch would never be checked anywhere if CI only ran one platform. The
    `types` task therefore runs mypy for BOTH darwin and linux; see mise.toml.
    """
    if sys.platform == "darwin":
        import fcntl

        # F_FULLFSYNC asks the drive to flush its internal cache, which plain
        # fsync does not do on Darwin. Not every filesystem implements it, so
        # fall back rather than failing a publish over a durability upgrade.
        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
            return
        except OSError:
            pass
    os.fsync(fd)


def fsync_path(path: Path) -> None:
    """Flush an already-written file to stable storage."""
    fd = os.open(path, os.O_RDONLY)
    try:
        _full_fsync(fd)
    finally:
        os.close(fd)


def fsync_parent(path: Path) -> None:
    """Flush the directory entry that names `path`.

    Directory fsync is unavailable on Windows; skipping there is correct rather
    than fatal, since the guarantee simply is not offered.
    """
    if os.name != "posix":
        return
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def staging_path(target: Path) -> Path:
    """The STABLE staging name for `target`, in the same directory.

    Shared by every invocation, so it is only safe under exclusive_lock. Used
    where a partial must be resumable across process restarts.
    """
    return target.with_name(target.name + STAGING_SUFFIX)


def new_staging_path(target: Path) -> Path:
    """A UNIQUE staging name beside `target`, created atomically.

    mkstemp has no race in the file's creation because it relies on O_EXCL, so
    two concurrent runs can never receive the same path. The file is created
    empty and left in place; the caller writes and then publishes it.

    Created in the target's own directory so that publishing is a
    same-filesystem replace rather than a cross-device copy.
    """
    fd, name = tempfile.mkstemp(dir=target.parent, prefix=f"{target.name}.", suffix=STAGING_SUFFIX)
    os.close(fd)
    return Path(name)


def lock_path(target: Path) -> Path:
    """The lock file guarding `target`. Its contents are irrelevant."""
    return target.with_name(target.name + LOCK_SUFFIX)


@contextmanager
def exclusive_lock(target: Path, *, timeout: float = DEFAULT_LOCK_TIMEOUT) -> Iterator[None]:
    """Hold an exclusive advisory lock covering `target`.

    Guards the whole check-and-commit sequence, not just the write. Checking
    state and then publishing without a lock leaves the classic TOCTOU window:
    both processes observe "not present", both do the work, and they race on the
    rename and the sidecar.

    The lock is kernel-enforced via flock and released automatically when the
    descriptor closes, including on abnormal termination -- so a crashed run
    cannot wedge the pipeline the way a stale PID file would.

    Non-blocking acquisition in a bounded poll loop rather than a blocking
    flock, so contention cannot hang a process forever and the failure names the
    file that was busy.
    """
    if os.name != "posix":
        # Advisory locking here is POSIX-only by design. Silently proceeding
        # unlocked would be worse than refusing: it would look safe.
        raise NotImplementedError("exclusive_lock requires a POSIX platform")

    import fcntl

    target.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path(target).open("w")
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"could not acquire the lock for {target} within "
                        f"{timeout:g}s; another process is working on it"
                    ) from None
                time.sleep(_LOCK_POLL_SECONDS)
        yield
    finally:
        # Closing releases the lock. The lock file itself is left behind on
        # purpose: unlinking it races with another process that has already
        # opened it and would let two holders coexist on different inodes.
        handle.close()


def publish(staged: Path, target: Path, *, durable: bool = True) -> None:
    """Atomically move a fully written staged file into its final place.

    `staged` must already be closed and complete. Set durable=False only where
    the artifact is cheaply reproducible and throughput matters more than
    surviving power loss; raw-layer data is neither.
    """
    if not staged.is_file():
        raise FileNotFoundError(f"nothing staged at {staged}")
    # SAME DIRECTORY BY IDENTITY, NOT BY SPELLING. os.path.samefile compares
    # device and inode, which is the actual question: mkstemp returns an
    # ABSOLUTE path while a caller may hold a relative target, so comparing
    # Path objects rejects a valid publish -- "datalake/raw" != "/abs/datalake/
    # raw" as strings while naming one directory. The tests never saw this
    # because tmp_path is always absolute; the real pipeline, run from the repo
    # root against relative config paths, failed on the first call.
    #
    # Not staged.resolve().parent either: that resolves the FILE and then takes
    # its parent, so a symlinked staging file would report the link target's
    # directory. samefile has no such ordering trap and needs no canonical form.
    if not staged.parent.samefile(target.parent):
        # A cross-directory publish may cross a filesystem, where replace raises
        # instead of silently degrading. Refusing up front turns a
        # deployment-specific runtime failure into an obvious programming error.
        raise ValueError(
            f"staged file must sit beside its target for an atomic replace: "
            f"{staged.parent} is not {target.parent}"
        )

    if durable:
        fsync_path(staged)

    staged.replace(target)

    if durable:
        fsync_parent(target)


def write_atomic(target: Path, data: str | bytes, *, durable: bool = True) -> None:
    """Write a small file so it is never observed partially written.

    For sidecars and manifests. A plain write_text can be interrupted and leave
    truncated JSON, which the next run then fails to parse -- strictly worse
    than the file being absent, because absent is recoverable by redoing the
    step while corrupt is not.

    Uses a unique staging name, so two processes writing the same sidecar cannot
    clobber each other's intermediate bytes; the final replace still decides a
    single winner.

    Small enough to hold in memory by design: this is for metadata, not data.
    Stream large payloads to a staged path and call publish() instead.
    """
    payload = data.encode() if isinstance(data, str) else data
    staged = new_staging_path(target)

    try:
        # fsync the descriptor we wrote through, before it is closed, so the
        # flush covers this file rather than whatever a later open references.
        with staged.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            if durable:
                _full_fsync(handle.fileno())

        staged.replace(target)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise

    if durable:
        fsync_parent(target)
