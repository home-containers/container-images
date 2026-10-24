"""Apply a narrow, lock-coherent dependency override during an image build only."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--brotlicffi-version", required=True)
    parser.add_argument("--base-image", required=True)
    args = parser.parse_args()
    root = Path("/opt/hermes")
    if Path.cwd() != root or not (root / "docker/build_agent.py").is_file():
        raise RuntimeError("unsupported base image: expected the reviewed Hermes image layout")
    if sys.version_info < (3, 14, 9):
        raise RuntimeError("managed Python is below 3.14.9; review PM's runtime pin before building")
    venv = root / ".venv"
    if venv.is_symlink() or not (venv / "pyvenv.cfg").is_file():
        raise RuntimeError("unsupported application environment layout")
    facts_path = root / "tools/facts.json"
    facts = json.loads(facts_path.read_text())
    extras = facts.get("packages", {}).get("venv", {}).get("extras")
    if not isinstance(extras, list) or not extras or not all(isinstance(x, str) for x in extras):
        raise RuntimeError("base image has no explicit shipped dependency selection")
    manifest = root / "pyproject.toml"
    lock = root / "uv.lock"
    original_manifest, original_lock = manifest.read_text(), lock.read_text()
    updated_manifest, _ = rewrite_brotlicffi_pin(original_manifest, args.brotlicffi_version)
    updated_manifest = allow_brotli_security_release(updated_manifest)
    changed = updated_manifest != original_manifest
    record_dir = Path("/usr/local/share/hermes-overlay")
    upstream = record_dir / "upstream"
    upstream.mkdir(exist_ok=True)
    (upstream / "pyproject.toml").write_text(original_manifest)
    (upstream / "uv.lock").write_text(original_lock)
    # PM's interpreter remains outside .venv; never select Debian's separate Python.
    interpreter = Path(sys.executable).resolve()
    sys.path.insert(0, str(root))
    from pm import build_environment, lock_project
    from pm.build_env import _record_selection
    cache = root / "uv-cache"
    if changed:
        manifest.write_text(updated_manifest)
        lock_project(root, python=interpreter, cache=cache, explicit=True)
        before, after = lock_identities(original_lock), lock_identities(lock.read_text())
        changed_names = {name for name in before.keys() | after.keys()
                         if before.get(name) != after.get(name)}
        root_name = tomllib.loads(original_manifest)["project"]["name"]
        if changed_names - {"brotlicffi", root_name}:
            raise RuntimeError("unrelated lock changes require review: " + ", ".join(sorted(changed_names)))
    # The PM builder requires a fresh destination. Rebuild at its final path so
    # console-script shebangs never refer to a renamed staging environment.
    shutil.rmtree(venv)
    build_environment(source=root, out=venv, python=interpreter, cache=cache,
                      extras=extras, no_install_project=True, frozen=True,
                      sealed=True, explicit=True)
    _record_selection(root, extras)
    subprocess.run([str(venv / "bin/python"), "-m", "docker.build_agent"], cwd=root, check=True)
    facts_path.chmod(0o644)
    (venv / ".lock").unlink(missing_ok=True)
    report = {
        "base_image": args.base_image,
        "brotlicffi_target": args.brotlicffi_version,
        "manifest_changed": changed,
        "managed_python": sys.version.split()[0],
        "managed_python_replaced": False,
        "extras": extras,
        "upstream_uv_lock_sha256": hashlib.sha256(original_lock.encode()).hexdigest(),
        "overlay_uv_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
        "scope": "Debian package refresh plus lock-coherent Python Brotli override; not a full CVE clearance",
    }
    (record_dir / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
