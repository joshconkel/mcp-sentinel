#!/usr/bin/env python3
"""
scripts/promote_staged.py

Promotes reviewed rule drafts from mcp_sentinel/rules/staged/ into
rules.yaml and checks/generic.py — automating steps 2, 4, and 5 of the
post-generation workflow.

What it does
------------
  1. Reads all MCPS-NNN-*-draft.yaml files from staged/
  2. Fixes greedy .* in regex patterns (replaces with .{0,40})
  3. Validates each draft against the rule schema
  4. For each passing draft, appends it to rules.yaml
  5. Adds the rule ID to _GENERIC_RULE_IDS in checks/generic.py
  6. Runs `mcp-sentinel rules validate` to confirm the result
  7. Moves promoted files to staged/promoted/ so staged/ stays clean

What it does NOT do (intentionally manual)
-------------------------------------------
  - Write test fixtures — you must verify each rule fires on real input
  - Change status from experimental to active — do that after fixture passes
  - Edit detection patterns beyond the .* → .{0,40} replacement

Usage
-----
  # Preview what would be promoted (no writes)
  python scripts/promote_staged.py --dry-run

  # Promote all passing drafts
  python scripts/promote_staged.py

  # Promote a single file
  python scripts/promote_staged.py --file mcp_sentinel/rules/staged/MCPS-029-atlas-AML-T0053-draft.yaml

  # Skip the .* fix (if you already reviewed patterns)
  python scripts/promote_staged.py --no-fix-regex

  # Keep staged files in place instead of moving to staged/promoted/
  python scripts/promote_staged.py --no-archive
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT   = Path(__file__).parent.parent
RULES_DIR   = REPO_ROOT / "mcp_sentinel" / "rules"
STAGED_DIR  = RULES_DIR / "staged"
ARCHIVE_DIR = STAGED_DIR / "promoted"
RULES_FILE  = RULES_DIR / "rules.yaml"
GENERIC_PY  = REPO_ROOT / "mcp_sentinel" / "checks" / "generic.py"

# ---------------------------------------------------------------------------
# Schema validation (mirrors engine.py expectations)
# ---------------------------------------------------------------------------

REQUIRED_FIELDS     = {"id", "name", "status", "severity", "category",
                       "detection_type", "description", "targets",
                       "detection", "mappings", "remediation"}
VALID_SEVERITIES    = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_DETECTIONS    = {"static", "dynamic", "both"}
VALID_STATUSES      = {"active", "experimental", "deprecated"}
VALID_PATTERN_TYPES = {"regex", "value_check", "schema_analysis", "unicode", "length"}

GREEDY_RE = re.compile(r'\.\*')


def validate_draft(rule: dict[str, Any]) -> list[str]:
    """Return a list of errors. Empty list = valid."""
    errors: list[str] = []

    missing = REQUIRED_FIELDS - set(rule.keys())
    if missing:
        errors.append(f"Missing fields: {sorted(missing)}")

    if rule.get("severity") not in VALID_SEVERITIES:
        errors.append(f"Invalid severity: {rule.get('severity')!r}")

    if rule.get("status") not in VALID_STATUSES:
        errors.append(f"Invalid status: {rule.get('status')!r}")

    if rule.get("detection_type") not in VALID_DETECTIONS:
        errors.append(f"Invalid detection_type: {rule.get('detection_type')!r}")

    patterns = rule.get("detection", {}).get("patterns", [])
    if not isinstance(patterns, list) or not patterns:
        errors.append("detection.patterns must be a non-empty list")
    else:
        for i, p in enumerate(patterns):
            if not isinstance(p, dict):
                errors.append(f"patterns[{i}] not a dict")
                continue
            if p.get("type") not in VALID_PATTERN_TYPES:
                errors.append(f"patterns[{i}].type={p.get('type')!r} not valid")
            if p.get("type") == "regex" and p.get("expression"):
                try:
                    flags = 0
                    for f in p.get("flags", []):
                        flags |= getattr(re, f, 0)
                    re.compile(p["expression"], flags)
                except re.error as exc:
                    errors.append(f"patterns[{i}] regex compile error: {exc}")

    if not isinstance(rule.get("mappings"), dict) or not rule["mappings"]:
        errors.append("mappings must be a non-empty dict")

    if not rule.get("targets"):
        errors.append("targets must be a non-empty list")

    return errors


# ---------------------------------------------------------------------------
# Regex tightening
# ---------------------------------------------------------------------------

def fix_greedy_regex(rule: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """
    Replace .* with .{0,40} in all regex pattern expressions.

    Returns (updated_rule, list_of_changes). The rule dict is modified
    in-place; the change list is for display only.
    """
    changes: list[str] = []
    patterns = rule.get("detection", {}).get("patterns", [])
    for p in patterns:
        if p.get("type") == "regex" and p.get("expression"):
            original = p["expression"]
            fixed    = GREEDY_RE.sub(".{0,40}", original)
            if fixed != original:
                p["expression"] = fixed
                changes.append(f"  .* → .{{0,40}}  in: {original[:70]}")
    return rule, changes


# ---------------------------------------------------------------------------
# rules.yaml helpers
# ---------------------------------------------------------------------------

def load_rules_yaml() -> dict[str, Any]:
    if not RULES_FILE.exists():
        return {"version": "1.0", "schema_version": "1.0",
                "last_updated": date.today().isoformat(), "rules": []}
    return yaml.safe_load(RULES_FILE.read_text(encoding="utf-8")) or {}


def existing_rule_ids(data: dict[str, Any]) -> set[str]:
    return {r["id"] for r in data.get("rules", [])}


def append_rule(data: dict[str, Any], rule: dict[str, Any]) -> None:
    """Append a rule to the in-memory rules dict and update last_updated."""
    data.setdefault("rules", []).append(rule)
    data["last_updated"] = date.today().isoformat()


def save_rules_yaml(data: dict[str, Any]) -> None:
    RULES_FILE.write_text(
        yaml.dump(data, default_flow_style=False, allow_unicode=True,
                  indent=2, sort_keys=False),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# generic.py helpers
# ---------------------------------------------------------------------------

# Matches the _GENERIC_RULE_IDS block — everything from the list open bracket
# to the closing bracket (multi-line).
_LIST_PATTERN = re.compile(
    r'(_GENERIC_RULE_IDS:\s*list\[str\]\s*=\s*\[)(.*?)(\])',
    re.DOTALL,
)

# Matches one entry line like:   "MCPS-006",   # Hidden Instructions...
_ENTRY_RE = re.compile(r'"(MCPS-\d+)"')


def load_generic_ids() -> list[str]:
    src = GENERIC_PY.read_text(encoding="utf-8")
    m = _LIST_PATTERN.search(src)
    if not m:
        return []
    return _ENTRY_RE.findall(m.group(2))


def add_id_to_generic(rule_id: str, rule_name: str, dry_run: bool = False) -> bool:
    """
    Append `rule_id` to _GENERIC_RULE_IDS in generic.py with a name comment.

    Returns True if the ID was added, False if it was already present.
    """
    src = GENERIC_PY.read_text(encoding="utf-8")
    m = _LIST_PATTERN.search(src)
    if not m:
        print(f"  ERROR: could not locate _GENERIC_RULE_IDS in {GENERIC_PY}")
        return False

    existing = _ENTRY_RE.findall(m.group(2))
    if rule_id in existing:
        return False   # already registered

    # Build the new entry line, matching the indentation style of existing entries
    new_entry = f'    "{rule_id}",   # {rule_name}\n'

    # Append before the closing bracket
    old_block = m.group(0)
    new_block = m.group(1) + m.group(2) + new_entry + m.group(3)

    if not dry_run:
        GENERIC_PY.write_text(src.replace(old_block, new_block, 1), encoding="utf-8")

    return True


# ---------------------------------------------------------------------------
# Validation runner
# ---------------------------------------------------------------------------

def run_validate() -> bool:
    """Run `mcp-sentinel rules validate` and return True if it passes."""
    result = subprocess.run(
        ["mcp-sentinel", "rules", "validate"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("  VALIDATION FAILED:")
        print(result.stdout[-800:] if result.stdout else "")
        print(result.stderr[-400:] if result.stderr else "")
        return False
    return True


# ---------------------------------------------------------------------------
# Main promotion logic
# ---------------------------------------------------------------------------

def promote(
    files: list[Path],
    dry_run: bool   = False,
    fix_regex: bool = True,
    archive: bool   = True,
) -> None:

    rules_data   = load_rules_yaml()
    existing_ids = existing_rule_ids(rules_data)
    generic_ids  = set(load_generic_ids())

    promoted = 0
    skipped  = 0
    failed   = 0

    print(f"\nmcp-sentinel rule promoter")
    print(f"Staged files: {len(files)}")
    print(f"Mode:         {'DRY RUN' if dry_run else 'write'}")
    print()

    for path in sorted(files):
        print(f"── {path.name}")

        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            print(f"   SKIP: YAML parse error — {exc}")
            failed += 1
            continue

        rule_id   = rule.get("id", "?")
        rule_name = rule.get("name", "?")

        # Already in rules.yaml
        if rule_id in existing_ids:
            print(f"   SKIP: {rule_id} already in rules.yaml")
            skipped += 1
            continue

        # Fix greedy regex
        if fix_regex:
            rule, regex_changes = fix_greedy_regex(rule)
            if regex_changes:
                print(f"   REGEX  {len(regex_changes)} pattern(s) tightened:")
                for c in regex_changes:
                    print(f"  {c}")

        # Validate
        errors = validate_draft(rule)
        if errors:
            print(f"   FAIL: validation errors ({len(errors)}):")
            for e in errors:
                print(f"     • {e}")
            print(f"   Fix the draft and re-run. Skipping.")
            failed += 1
            continue

        # Summary
        patterns  = rule.get("detection", {}).get("patterns", [])
        mappings  = list(rule.get("mappings", {}).keys())
        print(f"   {rule_id}  {rule.get('severity'):8}  {rule_name}")
        print(f"   targets:  {[t['field'] for t in rule.get('targets', [])]}")
        print(f"   patterns: {len(patterns)} ({', '.join(p['type'] for p in patterns)})")
        print(f"   maps to:  {', '.join(mappings)}")

        if dry_run:
            print(f"   DRY RUN — would add to rules.yaml and generic.py")
            promoted += 1
            continue

        # Append to rules.yaml
        append_rule(rules_data, rule)
        existing_ids.add(rule_id)

        # Add to generic.py
        if rule_id not in generic_ids:
            added = add_id_to_generic(rule_id, rule_name)
            if added:
                generic_ids.add(rule_id)
                print(f"   generic.py: added {rule_id}")
            else:
                print(f"   generic.py: {rule_id} already registered")
        else:
            print(f"   generic.py: {rule_id} already registered")

        # Archive the staged file
        if archive:
            ARCHIVE_DIR.mkdir(exist_ok=True)
            dest = ARCHIVE_DIR / path.name
            shutil.move(str(path), str(dest))
            print(f"   archived → staged/promoted/{path.name}")

        promoted += 1
        print()

    # Write rules.yaml once after all promotions
    if not dry_run and promoted > 0:
        save_rules_yaml(rules_data)
        print(f"Saved rules.yaml  ({len(rules_data['rules'])} total rules)")
        print()

        # Final validation pass
        print("Running: mcp-sentinel rules validate")
        if run_validate():
            print("Validation passed.\n")
        else:
            print("\nWARNING: validation failed after promotion. Check rules.yaml manually.\n")

    print(f"Done.  {promoted} promoted,  {skipped} skipped,  {failed} failed.")

    if not dry_run and promoted > 0:
        print("\nRemaining manual steps:")
        print("  1. Review each promoted rule's patterns in rules.yaml")
        print("  2. Write tests/fixtures/MCPS-NNN-malicious.json for each rule")
        print("  3. Run: pytest tests/ -v -k MCPS_NNN")
        print("  4. Change status: experimental → active once fixture passes")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Promote reviewed staged rule drafts into rules.yaml and generic.py.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--file", type=Path, default=None, metavar="PATH",
        help="Promote a single staged file instead of all files in staged/.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be promoted without writing anything.",
    )
    parser.add_argument(
        "--no-fix-regex", action="store_true",
        help="Skip the .* → .{0,40} regex replacement.",
    )
    parser.add_argument(
        "--no-archive", action="store_true",
        help="Leave staged files in place instead of moving to staged/promoted/.",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List staged files and their validation status, then exit.",
    )
    args = parser.parse_args()

    if args.file:
        if not args.file.exists():
            print(f"ERROR: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        files = [args.file]
    else:
        if not STAGED_DIR.exists():
            print(f"Staged directory does not exist: {STAGED_DIR}")
            print("Run the ATLAS ingestion script first to generate drafts.")
            sys.exit(0)
        files = [
            f for f in STAGED_DIR.glob("MCPS-*-draft.yaml")
            if f.parent == STAGED_DIR   # exclude staged/promoted/
        ]
        if not files:
            print(f"No draft files found in {STAGED_DIR}")
            print("Run the ATLAS ingestion script first.")
            sys.exit(0)

    if args.list:
        rules_data   = load_rules_yaml()
        existing_ids = existing_rule_ids(rules_data)
        generic_ids  = set(load_generic_ids())

        print(f"\nStaged drafts ({len(files)} files)\n")
        print(f"{'File':<55} {'Status':<12} {'Errors'}")
        print("-" * 85)
        for path in sorted(files):
            try:
                rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                print(f"{path.name:<55} PARSE ERROR  {exc}")
                continue

            rule_id = rule.get("id", "?")
            errors  = validate_draft(rule)
            greedy  = sum(
                1 for p in rule.get("detection", {}).get("patterns", [])
                if p.get("type") == "regex" and ".*" in p.get("expression", "")
            )

            if rule_id in existing_ids:
                status = "already in"
            elif errors:
                status = f"invalid({len(errors)})"
            elif greedy:
                status = f"greedy({greedy})"
            else:
                status = "ready"

            in_generic = "✓" if rule_id in generic_ids else "✗"
            print(
                f"{path.name:<55} {status:<12} "
                f"generic={in_generic}  "
                + (f"errors: {'; '.join(errors[:2])}" if errors else "")
            )
        return

    promote(
        files     = files,
        dry_run   = args.dry_run,
        fix_regex = not args.no_fix_regex,
        archive   = not args.no_archive,
    )


if __name__ == "__main__":
    main()
