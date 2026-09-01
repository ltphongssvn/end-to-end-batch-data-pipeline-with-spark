# scripts/evaluate_policies.py
"""Ask the composite policy one question about the source tree.

WHY THIS IS THIN. An earlier version looped over each policy, ran `opa eval`
per policy, and merged results in Python -- reimplementing what OPA composes
natively. policies/main/main.rego is the documented entrypoint pattern: it
composes the other policies and unions their deny reasons, so composition lives
in the policy language where opa test and coverage reach it. This script builds
the input, asks once, and reports.

WHY opa eval AND NOT conftest. Conftest is the better tool for validating
configuration FILES on disk and brings parsers for HCL, YAML and twenty other
formats. This input is generated runtime data -- an AST inventory produced by a
script -- which is the case OPA documents `eval` for.

WHY NOT --fail-defined ALONE. That flag sets exit 1 when a query is defined,
which would let OPA own the verdict without any Python. It is not enough here:
`opa eval` also exits non-zero when evaluation ERRORS, so the exit code would
conflate "the codebase violates policy" with "the engine could not answer".
Those need different responses, and treating the second as the first is how an
unverifiable control comes to look like a verified one.

    0  every policy allows
    1  VIOLATION: at least one policy denies, with attributed reasons
    2  UNDETERMINED: the inventory or the engine could not produce an answer
CI treats 1 and 2 alike; the distinction is for the human reading the log.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Final

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_DIR = REPO_ROOT / "policies"
INVENTORY = REPO_ROOT / "scripts" / "instrumentation_inventory.py"
DECISION_QUERY = "data.main.decision"

# RESOLVED ONCE, THEN EXECUTED BY ABSOLUTE PATH.
#
# Calling shutil.which("opa") to check existence and then
# subprocess.run(["opa", ...]) to execute resolves the name TWICE, so the
# check guarantees nothing about what actually runs. CVE-2026-32015 is that
# exact bug: an allowlist of binary NAMES was bypassed by controlling PATH, so
# a trojan with an allowlisted name ran despite the validation.
#
# Resolving at import and passing the absolute path means the binary that was
# checked is the binary that runs. It also satisfies ruff S607, which exists
# for this reason rather than as a style preference.
_OPA: Final = shutil.which("opa")

EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_UNDETERMINED = 2


def _undetermined(message: str) -> int:
    print(f"UNDETERMINED: {message}", file=sys.stderr)
    return EXIT_UNDETERMINED


def main() -> int:
    if _OPA is None:
        return _undetermined("opa is not installed; run 'mise install'")

    # S603 acknowledged per-site, not disabled project-wide: argv is a LIST so
    # no shell is involved, and every element is a module constant or a path
    # resolved above. The rule stays enabled so the next subprocess call that
    # DOES take user input is flagged rather than lost in a global ignore.
    built = subprocess.run(  # noqa: S603
        [sys.executable, str(INVENTORY)], capture_output=True, text=True, check=False
    )
    if built.returncode != 0:
        return _undetermined(f"inventory generation failed:\n{built.stderr.strip()}")

    # S603 acknowledged per-site, not disabled project-wide: argv is a LIST so
    # no shell is involved, and every element is a module constant or a path
    # resolved above. The rule stays enabled so the next subprocess call that
    # DOES take user input is flagged rather than lost in a global ignore.
    evaluated = subprocess.run(  # noqa: S603
        [
            _OPA,
            "eval",
            "--format",
            "json",
            "--data",
            str(POLICY_DIR),
            "--stdin-input",
            DECISION_QUERY,
        ],
        input=built.stdout,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if evaluated.returncode != 0:
        return _undetermined(f"opa eval failed:\n{evaluated.stderr.strip()}")

    try:
        payload = json.loads(evaluated.stdout)
        decision = payload["result"][0]["expressions"][0]["value"]
    except (json.JSONDecodeError, KeyError, IndexError) as exc:
        return _undetermined(f"unreadable decision ({exc})")

    versions = ", ".join(
        f"{name} {version}" for name, version in sorted(decision["policy_versions"].items())
    )

    if decision["allow"]:
        print(f"source policies satisfied: {versions}")
        return EXIT_OK

    print(f"POLICY VIOLATIONS ({versions}):", file=sys.stderr)
    for reason in sorted(decision["reasons"]):
        print(f"  {reason}", file=sys.stderr)
    return EXIT_VIOLATION


if __name__ == "__main__":
    raise SystemExit(main())
