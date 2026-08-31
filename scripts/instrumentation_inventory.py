# scripts/instrumentation_inventory.py
"""Build the instrumentation inventory the observability policy evaluates.

WHY AN AST WALK AND NOT grep. This project has been bitten repeatedly by grep
counting matches inside prose: a `shutil.move` in a docstring read as a call, a
`getinfo` in an explanatory paragraph read as usage. An inventory that counted a
mention of `emit(` in a comment would report a module as instrumented while it
emits nothing -- precisely the failure this gate exists to prevent. A parser sees
calls; prose is invisible to it.

Walking the AST for a call whose callee has a known name is the standard
pattern-matching form of static analysis, and it is sound for the question asked
here. Detecting the ABSENCE of a pattern is generally the hard case for
node-at-a-time analyzers, but at MODULE granularity it needs no dataflow: either
a call node exists somewhere in the tree or it does not.

STATED LIMITATION. Both the direct form `emit(...)` and the qualified form
`telemetry.emit(...)` are recognised, but an aliased import --
`from ... import emit as e` -- would not be. That is a deliberate bound rather
than an oversight: a gate that claims more precision than it has is worse than
one that states where it stops. Aliasing the emitter is also not something that
happens by accident, and the contract tests would still fail because the events
would not appear.

WHAT IT REPORTS, deliberately narrow:
    path               module path relative to the package root
    emits              number of emit CALLS, not mentions
    has_success_event  an emission carries Outcome.SUCCESS
    has_failure_event  an emission carries Outcome.FAILURE

Those are structural facts. Whether an event carries the RIGHT fields is
semantic and belongs to tests/test_telemetry.py; a policy claiming to judge it
would pass while the telemetry was useless.

Output is JSON on stdout so `opa eval --stdin-input` consumes it directly, with
diagnostics on stderr -- the stdout contract every CLI here follows.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "src" / "spark_batch_pipeline"

EMIT_NAME = "emit"
OUTCOME_ENUM = "Outcome"


def _is_emit_call(node: ast.AST) -> bool:
    """A call to emit(...) or telemetry.emit(...)."""
    if not isinstance(node, ast.Call):
        return False
    if isinstance(node.func, ast.Name):
        return node.func.id == EMIT_NAME
    if isinstance(node.func, ast.Attribute):
        return node.func.attr == EMIT_NAME
    return False


def _uses_outcome(tree: ast.AST, member: str) -> bool:
    """Whether Outcome.SUCCESS / Outcome.FAILURE appears as attribute ACCESS.

    Attribute access rather than a text search, so `Outcome.FAILURE` written in
    a comment explaining why something is deliberately NOT emitted cannot
    satisfy the check.
    """
    return any(
        isinstance(node, ast.Attribute)
        and node.attr == member
        and isinstance(node.value, ast.Name)
        and node.value.id == OUTCOME_ENUM
        for node in ast.walk(tree)
    )


def inventory(root: Path = PACKAGE_ROOT) -> list[dict[str, object]]:
    """One entry per module, sorted, so the policy input is deterministic."""
    modules: list[dict[str, object]] = []

    for path in sorted(root.rglob("*.py")):
        if path.name == "__init__.py" or "__pycache__" in path.parts:
            continue

        tree = ast.parse(path.read_text())
        modules.append(
            {
                "path": path.relative_to(root).as_posix(),
                "emits": sum(1 for node in ast.walk(tree) if _is_emit_call(node)),
                "has_success_event": _uses_outcome(tree, "SUCCESS"),
                "has_failure_event": _uses_outcome(tree, "FAILURE"),
            }
        )

    return modules


def main() -> int:
    if not PACKAGE_ROOT.is_dir():
        print(f"package root not found: {PACKAGE_ROOT}", file=sys.stderr)
        return 1

    modules = inventory()
    if not modules:
        # An empty inventory makes every policy rule vacuously true, so this
        # fails here rather than passing the gate by producing nothing.
        print("inventory is empty; refusing a vacuous result", file=sys.stderr)
        return 1

    print(json.dumps({"modules": modules}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
