"""Copy selected skills without replacing existing installations. Python 3.10+."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import stat
import sys


SKILLS_ROOT = Path(__file__).resolve().parents[1] / "skills"


def is_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except FileNotFoundError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def install(names: list[str], destination: Path, source_root: Path = SKILLS_ROOT) -> list[Path]:
    destination = Path(os.path.abspath(destination.expanduser()))
    source_root = source_root.resolve()
    names = list(dict.fromkeys(names))
    available = {p.name for p in source_root.iterdir() if p.is_dir() and (p / "SKILL.md").is_file()}
    if not names or any(name not in available for name in names):
        raise ValueError("Choose an available skill name.")
    for ancestor in (destination, *destination.parents):
        if is_link(ancestor):
            raise ValueError("The destination or an ancestor is a link/reparse point.")
    if destination.is_relative_to(source_root):
        raise ValueError("Installation destination must be outside the source skills directory.")
    targets = [destination / name for name in names]
    if any(os.path.lexists(target) for target in targets):
        raise FileExistsError("An installed skill already exists; no files were copied. Back up and compare it first.")
    for name in names:
        source = source_root / name
        if any(is_link(path) for path in (source, *source.rglob("*"))):
            raise ValueError("Source skills must not contain links/reparse points.")
    destination.mkdir(parents=True, exist_ok=True)
    installed = []
    for name, target in zip(names, targets):
        shutil.copytree(source_root / name, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"))
        installed.append(target)
    return installed


def main() -> int:
    available = sorted(p.name for p in SKILLS_ROOT.iterdir() if p.is_dir() and (p / "SKILL.md").is_file())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skill", action="append", choices=available, help="Repeat to select several; default: all")
    parser.add_argument("--dest", type=Path, default=Path.home() / ".agents" / "skills")
    args = parser.parse_args()
    try:
        for target in install(args.skill or available, args.dest):
            print(f"Installed: {target}")
    except (OSError, ValueError) as error:
        print(f"Installation stopped: {error}", file=sys.stderr)
        print("If a copy failed midway, inspect the target before retrying; existing files are never replaced.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
