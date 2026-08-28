# tests/test_task_shell.py
"""Guard: every mise task must parse under the interpreter mise will use.

WHY THIS EXISTS: `mise run check` passed on macOS and died on the Ubuntu CI
runner with `sh: 1: set: Illegal option -o pipefail`. mise defaults to
`sh -c -o errexit -o pipefail`, and `sh` is whatever the OS provides -- bash in
POSIX mode on macOS, dash on Ubuntu. The task bodies were fine; the interpreter
differed. That is environment drift, the same class as an unpinned runtime.

Two things are asserted here, and they are different claims:

  1. The interpreter is PINNED in mise.toml, so laptop, git hook, and CI runner
     all execute the identical shell. Without the pin, test 2 would be checking
     a shell that CI might not use.

  2. Every run script actually PARSES under that shell. A syntax error or a
     bashism in a task body is otherwise only discovered when CI runs it, which
     is minutes of feedback for a typo.

Parsing only (`-n`): nothing is executed, so this is safe and fast.
"""

from __future__ import annotations

import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

MISE_TOML = Path(__file__).resolve().parents[1] / "mise.toml"


def _config() -> dict[str, object]:
    return tomllib.loads(MISE_TOML.read_text())


def _run_scripts() -> list[tuple[str, str]]:
    """Every (task name, run script) pair defined in mise.toml."""
    tasks = _config().get("tasks", {})
    assert isinstance(tasks, dict)
    scripts: list[tuple[str, str]] = []
    for name, body in tasks.items():
        run = body.get("run") if isinstance(body, dict) else None
        if isinstance(run, str):
            scripts.append((name, run))
    return scripts


def test_task_shell_is_pinned() -> None:
    """Unpinned, mise falls back to the OS `sh`, which differs across platforms."""
    shell = _config().get("task_config", {})
    assert isinstance(shell, dict)
    assert shell.get("shell") == "bash -c", (
        "task_config.shell must pin bash. Without it mise uses the OS sh -- "
        "bash in POSIX mode on macOS, dash on Ubuntu -- and `set -o pipefail` "
        "is legal on one and fatal on the other."
    )


def test_tasks_were_discovered() -> None:
    """A parsing bug that found zero tasks would make every check below vacuous."""
    assert len(_run_scripts()) >= 10


@pytest.mark.parametrize("name,script", _run_scripts(), ids=lambda v: str(v)[:40])
def test_task_parses_under_pinned_shell(name: str, script: str) -> None:
    """`bash -n` parses without executing, so this is safe and fast."""
    bash = shutil.which("bash")
    assert bash, "bash not found; task_config.shell pins it"

    result = subprocess.run([bash, "-n"], input=script, capture_output=True, text=True, check=False)
    assert result.returncode == 0, f"task {name!r} does not parse:\n{result.stderr}"


@pytest.mark.parametrize("name,script", _run_scripts(), ids=lambda v: str(v)[:40])
def test_multiline_tasks_set_strict_mode(name: str, script: str) -> None:
    """A multi-line script without `set -e` continues after a failed line.

    Single-line tasks are exempt: there is no subsequent line to run, and the
    task's exit status is the command's.
    """
    if len(script.strip().splitlines()) <= 1:
        pytest.skip("single-line task")
    assert "set -euo pipefail" in script, (
        f"task {name!r} is multi-line but does not set strict mode, so a failing "
        "line would be ignored and the task would report success"
    )
