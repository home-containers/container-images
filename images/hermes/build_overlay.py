"""Read-only inventory and comparison of the shipped Hermes installation."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat


def preserved_snapshot(root: Path) -> dict[str, list]:
    """Hash shipped files, excluding only disposable caches and locks."""
    def excluded(relative: Path) -> bool:
        parts = relative.parts
        return (parts[0] == "uv-cache" or "__pycache__" in parts
                or relative.suffix == ".pyc" or relative.as_posix() == ".venv/.lock")

    result = {}
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in list(directories) + files:
            path = Path(directory) / name
            relative = path.relative_to(root)
            if excluded(relative):
                if name in directories:
                    directories.remove(name)
                continue
            mode = stat.S_IMODE(path.lstat().st_mode)
            if path.is_symlink():
                result[relative.as_posix()] = ["link", mode, os.readlink(path)]
                if name in directories:
                    directories.remove(name)
            elif path.is_file():
                with path.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                result[relative.as_posix()] = ["file", mode, digest]
    return result


def compare_snapshots(before: dict[str, list], after: dict[str, list]) -> None:
    """Reject incomplete preservation evidence before comparing shipped files."""
    required = {
        "manifest.json", "install-stamp.json", "run_agent.py", "libexec/hermes",
        ".venv/pyvenv.cfg", ".venv/bin/python",
    }
    groups = (
        r"hermes_cli/web_dist/.+",
        r"(?:hermes_cli/tui_dist|ui-tui/dist)/.+",
        r"tools/python-[^/]+/.+",
        r"tools/node-[^/]+/.+",
        r"\.venv/lib/python[^/]+/site-packages/httpx/.+",
    )
    for label, inventory in (("upstream", before), ("derived", after)):
        if not inventory:
            raise RuntimeError(f"{label} inventory coverage is empty")
        missing = sorted(required - inventory.keys())
        missing.extend(pattern for pattern in groups
                       if not any(re.fullmatch(pattern, name) for name in inventory))
        if missing:
            raise RuntimeError(f"{label} inventory coverage missing: " + ", ".join(missing))
    unexpected = sorted(name for name in before.keys() | after.keys()
                        if before.get(name) != after.get(name))
    if unexpected:
        raise RuntimeError("shipped files changed: " + ", ".join(unexpected[:20]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--snapshot-only", action="store_true")
    mode.add_argument("--compare-snapshots", nargs=2, type=Path, metavar=("UPSTREAM", "DERIVED"))
    args = parser.parse_args()
    if args.compare_snapshots:
        before, after = (json.loads(path.read_text()) for path in args.compare_snapshots)
        compare_snapshots(before, after)
        print("Upstream application, frontends, runtimes and unrelated dependencies preserved: "
              f"{len(before)} files")
        return
    root = Path("/opt/hermes")
    if args.snapshot_only:
        print(json.dumps(preserved_snapshot(root), sort_keys=True))
        return


if __name__ == "__main__":
    main()
