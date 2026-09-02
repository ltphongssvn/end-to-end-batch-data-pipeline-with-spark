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


def _passes_duration(tree: ast.AST) -> bool:
    """Whether any call passes a `duration=` keyword argument.

    A keyword in a CALL, not a mention. The field existed in the contract, the
    timing helper existed and was tested, and no production code ever populated
    it -- nine green gates missed that, because nothing checked whether the
    value was actually produced.
    """
    return any(
        isinstance(node, ast.Call) and any(keyword.arg == "duration" for keyword in node.keywords)
        for node in ast.walk(tree)
    )


def _direct_imports(tree: ast.AST) -> set[str]:
    """Root package of every import in the module.

    Root only: pyspark.sql.functions and pyspark are the same dependency for
    a layering rule, and recording full dotted paths would force the policy
    to enumerate submodules it cannot know in advance.
    """
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            roots.add(node.module)
    return roots


def _internal_target(module: str, known: set[str]) -> str | None:
    """Map an import onto a module path inside this package, or None."""
    prefix = "spark_batch_pipeline."
    if not module.startswith(prefix):
        return None
    candidate = module[len(prefix) :].replace(".", "/") + ".py"
    return candidate if candidate in known else None


def _transitive(direct: dict[str, set[str]], externals: dict[str, set[str]]) -> dict[str, set[str]]:
    """Effective external dependencies, following internal imports.

    THE POINT OF THE CLOSURE. A flat scan says ingest/extract.py does not
    import pyspark, and that is true and insufficient: if it imported
    session.py, which imports pyspark, the dependency would be just as real
    and completely invisible. Import Linter follows indirect chains for
    exactly this reason; computing the closure here keeps enforcement in one
    engine instead of adding a second tool that overlaps OPA.

    Iterates to a fixed point rather than recursing, so an import cycle
    terminates instead of overflowing the stack.
    """
    effective = {path: set(deps) for path, deps in externals.items()}
    changed = True
    while changed:
        changed = False
        for path, internals in direct.items():
            for target in internals:
                merged = effective[path] | effective.get(target, set())
                if merged != effective[path]:
                    effective[path] = merged
                    changed = True
    return effective


def inventory(root: Path = PACKAGE_ROOT) -> list[dict[str, object]]:
    """One entry per module, sorted, so the policy input is deterministic."""
    trees: dict[str, ast.AST] = {}
    for path in sorted(root.rglob("*.py")):
        if path.name == "__init__.py" or "__pycache__" in path.parts:
            continue
        trees[path.relative_to(root).as_posix()] = ast.parse(path.read_text())

    known = set(trees)
    direct_internal: dict[str, set[str]] = {}
    externals: dict[str, set[str]] = {}
    for name, tree in trees.items():
        internal: set[str] = set()
        external: set[str] = set()
        for imported in _direct_imports(tree):
            target = _internal_target(imported, known)
            if target is not None:
                internal.add(target)
            else:
                external.add(imported.split(".")[0])
        direct_internal[name] = internal
        externals[name] = external

    effective = _transitive(direct_internal, externals)

    modules: list[dict[str, object]] = []
    for name, tree in trees.items():
        path = root / name
        modules.append(
            {
                "path": name,
                "emits": sum(1 for node in ast.walk(tree) if _is_emit_call(node)),
                "has_success_event": _uses_outcome(tree, "SUCCESS"),
                "has_failure_event": _uses_outcome(tree, "FAILURE"),
                "reports_duration": _passes_duration(tree),
                "imports": sorted(externals[name]),
                "effective_imports": sorted(effective[name]),
            }
        )

    return modules


LOCKFILE = PACKAGE_ROOT.parents[1] / "uv.lock"


def locked_packages() -> dict[str, str]:
    """Every package uv resolved, name -> version, read from uv.lock.

    WHY THE LOCKFILE AND NOT THE IMPORTS. An import check catches
    `import dagster` and completely misses `uv add dagster` -- and the damage
    is done by the INSTALL, not the import. Resolving dagster here downgrades
    protobuf from 7.36.0 to 6.33.6 underneath a Spark Connect client, which
    surfaces as UDFs failing against Databricks rather than as any import a
    parser could see.

    Parsed with a narrow reader rather than a TOML library because the shape
    needed is two fields per [[package]] block, and adding a dependency to the
    script that guards dependencies is its own small irony.
    """
    if not LOCKFILE.is_file():
        return {}

    packages: dict[str, str] = {}
    name = ""
    for line in LOCKFILE.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("name = "):
            name = stripped.split('"')[1]
        elif stripped.startswith("version = ") and name:
            packages[name] = stripped.split('"')[1]
            name = ""
    return packages


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

    payload = {"modules": modules, "locked_packages": locked_packages()}
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
