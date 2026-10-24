"""Apply a narrow, lock-coherent dependency override during an image build only."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import os
import stat
import subprocess
import sys
import tomllib


FIXED_BROTLICFFI = (1, 2, 1, 0)


def rewrite_brotlicffi_pin(text: str, target: str) -> tuple[str, bool]:
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", target):
        raise ValueError("brotlicffi target must be a four-component numeric version")
    wanted = tuple(map(int, target.split(".")))
    if wanted < FIXED_BROTLICFFI:
        raise ValueError("brotlicffi target is below the fixed security release")
    project = tomllib.loads(text).get("project", {})
    requirements = list(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        requirements.extend(group)
    matches = [re.fullmatch(r"brotlicffi==(\d+\.\d+\.\d+\.\d+)", item)
               for item in requirements]
    pins = [match.group(1) for match in matches if match is not None]
    if len(pins) != 1:
        raise ValueError("expected exactly one supported exact brotlicffi pin; review upstream layout")
    previous = pins[0]
    if tuple(map(int, previous.split("."))) > wanted:
        raise ValueError("refusing to downgrade a newer upstream brotlicffi pin")
    if previous == target:
        return text, False
    pattern = r"([\"'])brotlicffi==" + re.escape(previous) + r"\1"
    replacement = lambda match: match.group(1) + "brotlicffi==" + target + match.group(1)
    updated, count = re.subn(pattern, replacement, text)
    if count != 1:
        raise ValueError("expected exactly one unambiguous textual brotlicffi pin")
    return updated, True


def allow_brotli_security_release(text: str) -> str:
    """Exempt only the reviewed, exact Brotli fix from upstream's release-age gate."""
    policy = tomllib.loads(text).get("tool", {}).get("uv", {})
    if not policy.get("exclude-newer"):
        return text
    exceptions = policy.get("exclude-newer-package", {})
    if exceptions.get("brotlicffi") is False:
        return text
    if "brotlicffi" in exceptions:
        raise ValueError("existing Brotli release-age policy needs review")
    pattern = r"(?m)^(exclude-newer-package\s*=\s*)\{([^\n{}]*)\}([ \t]*(?:#[^\n]*)?)$"

    def replacement(match):
        body = match.group(2).strip().rstrip(",")
        body = (body + ", ") if body else ""
        return ("# Downstream exception: exact CVE-2026-111497 fix; retain the global age gate.\n"
                + match.group(1) + "{ " + body + "brotlicffi = false }" + match.group(3))

    updated, count = re.subn(pattern, replacement, text)
    if count != 1 or tomllib.loads(updated)["tool"]["uv"]["exclude-newer-package"].get("brotlicffi") is not False:
        raise ValueError("unsupported release-age policy layout; review upstream changes")
    return updated


def lock_identities(text: str) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for package in tomllib.loads(text).get("package", []):
        identity = json.dumps(package, sort_keys=True)
        result.setdefault(package["name"], set()).add(identity)
    return result


def locked_brotli_requirement(text: str, target: str) -> str:
    packages = [item for item in tomllib.loads(text).get("package", [])
                if item.get("name") == "brotlicffi"]
    if len(packages) != 1 or packages[0].get("version") != target:
        raise ValueError("expected exactly one Brotli lock entry at the reviewed target")
    package = packages[0]
    if package.get("source") != {"registry": "https://pypi.org/simple"}:
        raise ValueError("Brotli override requires the reviewed PyPI registry")
    hashes = sorted({wheel.get("hash", "") for wheel in package.get("wheels", [])})
    if not hashes or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in hashes):
        raise ValueError("Brotli lock entry needs valid SHA-256 wheel hashes")
    return f"brotlicffi=={target} " + " ".join("--hash=" + value for value in hashes) + "\n"


def preserved_snapshot(root: Path) -> dict[str, list]:
    """Hash shipped files, excluding only reviewed mutations and disposable caches."""
    def excluded(relative: Path) -> bool:
        parts = relative.parts
        name = relative.as_posix()
        if parts[0] == "uv-cache" or "__pycache__" in parts or relative.suffix == ".pyc":
            return True
        if name in {"pyproject.toml", "uv.lock", "tools/facts.json", ".venv/.lock"}:
            return True
        if re.fullmatch(r"hermes_agent-[^/]+\.dist-info/METADATA", name):
            return True
        return (len(parts) >= 5 and parts[:2] == (".venv", "lib")
                and parts[3] == "site-packages"
                and (parts[4] in {"brotlicffi", "brotlicffi.libs"}
                     or re.fullmatch(r"brotlicffi-[^/]+\.dist-info", parts[4]) is not None))

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
        r"hermes_cli/tui_dist/.+",
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
        raise RuntimeError("unrelated shipped files changed: " + ", ".join(unexpected[:20]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--brotlicffi-version")
    parser.add_argument("--base-image")
    mode = parser.add_mutually_exclusive_group()
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
    if not args.brotlicffi_version or not args.base_image:
        parser.error("--brotlicffi-version and --base-image are required for an override")
    if Path.cwd() != root or not (root / "manifest.json").is_file():
        raise RuntimeError("unsupported base image: expected the reviewed Hermes image layout")
    if sys.version_info < (3, 14, 9):
        raise RuntimeError("managed Python is below 3.14.9; review its runtime pin")
    venv = root / ".venv"
    if venv.is_symlink() or not (venv / "pyvenv.cfg").is_file():
        raise RuntimeError("unsupported application environment layout")
    facts_path = root / "tools/facts.json"
    facts = json.loads(facts_path.read_text())
    facts_mode = stat.S_IMODE(facts_path.stat().st_mode)
    selection = facts.get("packages", {}).get("venv", {})
    if set(selection) != {"stamp", "extras"}:
        raise RuntimeError("expected shipped environment only, not a runtime/plugin generation")
    extras = selection["extras"]
    if not isinstance(extras, list) or not extras or not all(isinstance(x, str) for x in extras):
        raise RuntimeError("base image has no explicit shipped dependency selection")
    uv = root / "tools" / facts["packages"]["uv"]["entry"] / "uv"
    if not uv.resolve().is_relative_to((root / "tools").resolve()) or not uv.is_file():
        raise RuntimeError("bundled uv executable is missing or outside the managed store")
    manifest, lock = root / "pyproject.toml", root / "uv.lock"
    original_manifest, original_lock = manifest.read_text(), lock.read_text()
    project = tomllib.loads(original_manifest)["project"]
    dist_name = re.sub(r"[-_.]+", "_", project["name"])
    metadata = root / f"{dist_name}-{project['version']}.dist-info/METADATA"
    original_metadata = metadata.read_text()
    declaration = r"(?m)^(Requires-Dist: brotlicffi==)(\d+\.\d+\.\d+\.\d+)(?=;|[ \t]*$)"
    versions = re.findall(declaration, original_metadata)
    if len(versions) != 1:
        raise RuntimeError("expected exactly one static Brotli dependency declaration")
    if tuple(map(int, versions[0][1].split("."))) > tuple(map(int, args.brotlicffi_version.split("."))):
        raise RuntimeError("refusing to downgrade distribution metadata")
    updated_manifest, _ = rewrite_brotlicffi_pin(original_manifest, args.brotlicffi_version)
    updated_manifest = allow_brotli_security_release(updated_manifest)
    changed = updated_manifest != original_manifest
    baseline = preserved_snapshot(root)
    record_dir = Path("/usr/local/share/hermes-overlay")
    upstream = record_dir / "upstream"
    upstream.mkdir(exist_ok=True)
    (upstream / "pyproject.toml").write_text(original_manifest)
    (upstream / "uv.lock").write_text(original_lock)
    (upstream / "METADATA").write_text(original_metadata)
    interpreter = Path(sys.executable).resolve()
    sys.path.insert(0, str(root))
    from pm import lock_project
    from pm.build_env import _record_selection
    from pm.environment import managed_environment
    cache = root / "uv-cache"
    if changed:
        manifest.write_text(updated_manifest)
        lock_project(root, python=interpreter, cache=cache, explicit=True)
        before, after = lock_identities(original_lock), lock_identities(lock.read_text())
        changed_names = {name for name in before.keys() | after.keys()
                         if before.get(name) != after.get(name)}
        if changed_names - {"brotlicffi", project["name"]}:
            raise RuntimeError("unrelated lock changes require review: " + ", ".join(sorted(changed_names)))
    requirements = record_dir / "brotlicffi-requirements.txt"
    requirements.write_text(locked_brotli_requirement(lock.read_text(), args.brotlicffi_version))
    # Explicit downstream build-only exception: PM has no hash-enforced,
    # single-package mutation API. Never sync/recreate the full environment.
    subprocess.run([
        str(uv), "pip", "install", "--no-config", "--no-sources",
        "--python", str(venv / "bin/python"), "--no-deps", "--require-hashes",
        "--only-binary=:all:", "--reinstall-package", "brotlicffi",
        "--index-url", "https://pypi.org/simple", "--cache-dir", str(cache),
        "--requirements", str(requirements),
    ], cwd=root, check=True, timeout=600)
    metadata.write_text(re.sub(declaration, lambda match: match.group(1) + args.brotlicffi_version,
                               original_metadata))
    managed_environment(venv, python=interpreter, cache=cache, explicit=True).check(lock)
    after = preserved_snapshot(root)
    unexpected = sorted(name for name in baseline.keys() | after.keys()
                        if baseline.get(name) != after.get(name))
    if unexpected:
        raise RuntimeError("unrelated shipped files changed: " + ", ".join(unexpected[:20]))
    _record_selection(root, extras)
    facts_path.chmod(facts_mode)
    new_facts = json.loads(facts_path.read_text())
    expected_facts = json.loads(json.dumps(facts))
    expected_facts["packages"]["venv"] = new_facts["packages"]["venv"]
    if new_facts != expected_facts or sorted(new_facts["packages"]["venv"]["extras"]) != sorted(extras):
        raise RuntimeError("unrelated managed facts or selected extras changed")
    (venv / ".lock").unlink(missing_ok=True)
    report = {
        "base_image": args.base_image, "brotlicffi_target": args.brotlicffi_version,
        "manifest_changed": changed, "managed_python": sys.version.split()[0],
        "managed_python_replaced": False, "venv_recreated": False,
        "application_rebuilt": False, "extras": extras,
        "preserved_file_count": len(baseline), "unrelated_files_changed": [],
        "preserved_inventory_sha256": hashlib.sha256(json.dumps(baseline, sort_keys=True).encode()).hexdigest(),
        "upstream_uv_lock_sha256": hashlib.sha256(original_lock.encode()).hexdigest(),
        "overlay_uv_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
        "scope": "Published upstream image plus Debian refresh and one in-place, hash-locked Python dependency override",
    }
    (record_dir / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
