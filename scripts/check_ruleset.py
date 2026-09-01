# scripts/check_ruleset.py
"""Verify that develop and main are actually protected on the server.

WHY THIS EXISTS: the ruleset lives in GitHub's state, not in the repository. It
was verified empirically to refuse direct pushes, force pushes and deletion on
both branches -- and nothing here would have noticed if someone deleted it. A
protection whose absence you cannot detect is one you cannot rely on.

WHICH ENDPOINT, AND WHY IT MATTERS
This reads /repos/{repo}/rules/branches/{branch}, NOT /rulesets.

/rulesets requires repository-admin rights, and `administration` is not a
grantable permission for a workflow's GITHUB_TOKEN. A scheduled job built on it
would report UNDETERMINED every single day -- and a job that always fails gets
muted, at which point it protects nothing. That is a failure this design avoids
rather than inherits.

/rules/branches also answers a better question. It reports the EFFECTIVE rules
applying to a branch whatever their source, so a ruleset that was renamed,
replaced or layered still passes when the protection genuinely holds, and no
amount of configuration bookkeeping can hide an unprotected branch.

WHAT IS ASSERTED: the rule TYPES that must apply. Exact parameters live in
.github/rulesets/ for reference and re-creation, but asserting them here would
report drift whenever GitHub adds a field -- as it did with
require_extra_approval_for_unattributed_changes, which appeared without ever
being set. The types are the guarantee; the parameters are detail.

WHY gh RATHER THAN httpx, which this project already depends on: gh resolves
authentication once, from the keychain locally and GH_TOKEN in CI. Using httpx
would mean re-implementing token handling and error mapping for a single
endpoint. A missing gh is reported as UNDETERMINED rather than silently passing.

EXIT CODES are distinct on purpose:
    0  every required rule applies to every protected branch
    1  UNPROTECTED: a required rule is missing
    2  UNDETERMINED: the check could not run (no gh, no auth, no network)
CI treats 1 and 2 alike, because an unverifiable protection is not a verified
one. The distinction is for the human reading the log.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from typing import Final

REPO = "ltphongssvn/end-to-end-batch-data-pipeline-with-spark"
PROTECTED_BRANCHES = ("develop", "main")

# What each protected branch must enforce, and what each rule buys:
#   pull_request           no direct pushes; changes arrive through review
#   required_status_checks the quality gate must pass before a merge
#   non_fast_forward       history cannot be rewritten
#   deletion               the branch cannot be removed
REQUIRED_RULES = frozenset(
    {"pull_request", "required_status_checks", "non_fast_forward", "deletion"}
)

# RESOLVED ONCE, THEN EXECUTED BY ABSOLUTE PATH.
#
# Calling shutil.which("gh") to check existence and then
# subprocess.run(["gh", ...]) to execute resolves the name TWICE, so the
# check guarantees nothing about what actually runs. CVE-2026-32015 is that
# exact bug: an allowlist of binary NAMES was bypassed by controlling PATH, so
# a trojan with an allowlisted name ran despite the validation.
#
# Resolving at import and passing the absolute path means the binary that was
# checked is the binary that runs. It also satisfies ruff S607, which exists
# for this reason rather than as a style preference.
_GH: Final = shutil.which("gh")

EXIT_OK = 0
EXIT_UNPROTECTED = 1
EXIT_UNDETERMINED = 2


def _undetermined(message: str) -> int:
    print(f"UNDETERMINED: {message}", file=sys.stderr)
    return EXIT_UNDETERMINED


def _effective_rules(branch: str) -> set[str] | None:
    """Rule types applying to `branch`, or None if it could not be determined."""
    # S603 acknowledged per-site, not disabled project-wide: argv is a LIST so
    # no shell is involved, and every element is a module constant or a path
    # resolved above. The rule stays enabled so the next subprocess call that
    # DOES take user input is flagged rather than lost in a global ignore.
    result = subprocess.run(  # noqa: S603
        [_GH, "api", f"repos/{REPO}/rules/branches/{branch}"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        print(result.stderr.strip(), file=sys.stderr)
        return None
    return {rule["type"] for rule in json.loads(result.stdout)}


def main() -> int:
    if _GH is None:
        return _undetermined("gh is not installed")

    failures: list[str] = []

    for branch in PROTECTED_BRANCHES:
        applied = _effective_rules(branch)
        if applied is None:
            return _undetermined(f"could not read effective rules for {branch}")

        missing = REQUIRED_RULES - applied
        if missing:
            failures.append(f"  {branch}: MISSING {sorted(missing)} (applied: {sorted(applied)})")
        else:
            enforced = ", ".join(sorted(applied & REQUIRED_RULES))
            print(f"  {branch}: protected ({enforced})")

    if failures:
        print("\nUNPROTECTED branches found:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        print(
            "\nRestore from the committed policy:\n"
            f"  gh api -X POST repos/{REPO}/rulesets \\\n"
            "    --input .github/rulesets/develop-and-main-protection.json",
            file=sys.stderr,
        )
        return EXIT_UNPROTECTED

    print("all protected branches enforce every required rule")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
