"""Offline structural checks for this repository; no third-party dependencies."""
from __future__ import annotations

import ast
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    errors = []
    skills = sorted((ROOT / "skills").glob("*/SKILL.md"))
    if not skills:
        errors.append("No skills found")
    for manifest in skills:
        text = manifest.read_text(encoding="utf-8")
        match = re.match(r"\A---\n(.*?)\n---(?:\n|$)", text, re.S)
        if not match:
            errors.append(f"{manifest.relative_to(ROOT)}: missing frontmatter")
            continue
        header = match.group(1)
        name = re.search(r"^name: ([a-z0-9-]+)$", header, re.M)
        if not name or name.group(1) != manifest.parent.name:
            errors.append(f"{manifest.relative_to(ROOT)}: invalid name")
        if not re.search(r"^description: \S.+$", header, re.M):
            errors.append(f"{manifest.relative_to(ROOT)}: missing single-line description")
    files = sorted(p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.relative_to(ROOT).parts and "__pycache__" not in p.parts)
    for path in files:
        relative = path.relative_to(ROOT)
        try:
            if path.suffix == ".json":
                json.loads(path.read_text(encoding="utf-8"))
            if path.suffix == ".py":
                ast.parse(path.read_text(encoding="utf-8"), filename=str(relative))
            if path.suffix == ".md":
                text = path.read_text(encoding="utf-8")
                for target in re.findall(r"\]\(([^\s)]+)\)", text):
                    if "://" in target or target.startswith(("#", "mailto:")):
                        continue
                    resolved = (path.parent / target.split("#", 1)[0]).resolve()
                    if not resolved.is_relative_to(ROOT) or not resolved.exists():
                        errors.append(f"{relative}: broken/nonportable link {target}")
        except (ValueError, OSError, SyntaxError) as error:
            errors.append(f"{relative}: {type(error).__name__}")
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print(f"Validated {len(skills)} skills and {len(files)} files (structure, links, JSON and Python syntax).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
