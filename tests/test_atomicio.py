# tests/test_atomicio.py
"""Commit-boundary tests.

Durability against real power loss cannot be tested without cutting power, so
these assert the properties that ARE observable: the syscall actually used, the
absence of a copy-then-delete fallback, refusal of a cross-directory publish,
and that nothing partial survives. The fsync calls are asserted by observing
that they are issued, since their effect is invisible from userspace.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from spark_batch_pipeline import atomicio
from spark_batch_pipeline.atomicio import fsync_parent, fsync_path, publish

PAYLOAD = b"country,year,value\nABW,1960,1.0\n" * 50


def test_publish_moves_content_and_removes_staged(tmp_path: Path) -> None:
    staged = tmp_path / "data.csv.part"
    target = tmp_path / "data.csv"
    staged.write_bytes(PAYLOAD)

    publish(staged, target)

    assert target.read_bytes() == PAYLOAD
    assert not staged.exists(), "staged file must not survive a publish"


def test_publish_overwrites_an_existing_target(tmp_path: Path) -> None:
    """replace() semantics: the target is replaced, not refused."""
    staged = tmp_path / "data.csv.part"
    target = tmp_path / "data.csv"
    target.write_bytes(b"stale")
    staged.write_bytes(PAYLOAD)

    publish(staged, target)

    assert target.read_bytes() == PAYLOAD


def test_publish_uses_replace_not_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The whole point of not using shutil.move.

    shutil.move degrades to copy-then-delete across filesystems, which is not
    atomic and fails silently. Path.replace is the os.replace syscall and either
    performs a same-filesystem replace or raises. Asserting the inode survives
    proves a rename happened rather than a copy.
    """
    staged = tmp_path / "data.csv.part"
    target = tmp_path / "data.csv"
    staged.write_bytes(PAYLOAD)
    staged_inode = staged.stat().st_ino

    publish(staged, target)

    assert target.stat().st_ino == staged_inode, "content was copied, not renamed"


def test_publish_refuses_cross_directory(tmp_path: Path) -> None:
    """A cross-directory publish may cross a filesystem, where replace raises.

    Refusing up front turns a deployment-specific runtime failure into an
    obvious programming error at the call site.
    """
    other = tmp_path / "elsewhere"
    other.mkdir()
    staged = other / "data.csv.part"
    staged.write_bytes(PAYLOAD)

    with pytest.raises(ValueError, match="beside its target"):
        publish(staged, tmp_path / "data.csv")

    assert staged.exists(), "a refused publish must not consume the staged file"


def test_publish_requires_a_staged_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="nothing staged"):
        publish(tmp_path / "absent.part", tmp_path / "absent")


def test_publish_fsyncs_file_then_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Order matters: contents durable BEFORE the name, name durable AFTER.

    Without the parent fsync the bytes can be durable while the directory entry
    pointing at them is not, so a crash can leave the file under its old name
    or under none at all.
    """
    calls: list[str] = []
    monkeypatch.setattr(atomicio, "fsync_path", lambda p: calls.append("file"))
    monkeypatch.setattr(atomicio, "fsync_parent", lambda p: calls.append("parent"))

    staged = tmp_path / "data.csv.part"
    target = tmp_path / "data.csv"
    staged.write_bytes(PAYLOAD)

    publish(staged, target)

    assert calls == ["file", "parent"]


def test_durable_false_skips_syncing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(atomicio, "fsync_path", lambda p: calls.append("file"))
    monkeypatch.setattr(atomicio, "fsync_parent", lambda p: calls.append("parent"))

    staged = tmp_path / "data.csv.part"
    target = tmp_path / "data.csv"
    staged.write_bytes(PAYLOAD)

    publish(staged, target, durable=False)

    assert calls == []
    assert target.read_bytes() == PAYLOAD


def test_fsync_helpers_do_not_raise_on_real_files(tmp_path: Path) -> None:
    """Exercises the real syscalls, including F_FULLFSYNC on macOS."""
    target = tmp_path / "data.csv"
    target.write_bytes(PAYLOAD)

    fsync_path(target)
    fsync_parent(target)


def test_fsync_parent_is_a_noop_off_posix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows offers no directory fsync, so skipping is correct, not fatal."""
    target = tmp_path / "data.csv"
    target.write_bytes(PAYLOAD)
    monkeypatch.setattr(os, "name", "nt")

    fsync_parent(target)
