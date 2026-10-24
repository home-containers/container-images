#!/usr/bin/env python3
"""Narrow, stdlib-only Camofox overlay; never install application dependencies."""
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import re
from urllib.parse import urlsplit
import shutil
import zipfile
import mmap
import tempfile
import urllib.request
import urllib.error
import subprocess


def probe_node(path):
    code = """const z = require('node:zlib');
const d = Buffer.from('overlay-node-roundtrip');
if (!z.brotliDecompressSync(z.brotliCompressSync(d)).equals(d)) throw new Error('roundtrip');
console.log(JSON.stringify({version: process.versions.node, brotli: process.versions.brotli,
marker: z.constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH ?? null}));"""
    result = subprocess.run([str(path), "-e", code], check=True, text=True, capture_output=True,
                            timeout=120, env={k: v for k, v in os.environ.items()
                                              if k not in ("NODE_OPTIONS", "NODE_PATH")})
    return json.loads(result.stdout)


def install_node(candidate, target, minimum, probe=probe_node):
    candidate, target = Path(candidate), Path(target)
    if target.is_symlink() or not target.is_file() or not candidate.is_file():
        raise ValueError("expected regular inherited Node and donor candidate")
    current, proposed = probe(target), probe(candidate)
    action = select_node(current, proposed, minimum)
    before_hash = file_hash(target)
    if action == "replace":
        mode = stat.S_IMODE(target.stat().st_mode)
        with tempfile.NamedTemporaryFile(prefix=".node-overlay-", dir=target.parent, delete=False) as stream:
            staging = Path(stream.name)
        try:
            shutil.copyfile(candidate, staging)
            staging.chmod(mode)
            if file_hash(staging) != file_hash(candidate):
                raise ValueError("Node binary copy hash mismatch")
            os.replace(staging, target)
        finally:
            staging.unlink(missing_ok=True)
    return {"action": action, "before": current, "selected": current if action == "keep" else proposed,
            "before_sha256": before_hash, "sha256": file_hash(target), "candidate_sha256": file_hash(candidate)}


def browser_evidence(target):
    target = Path(target)
    metadata = json.loads((target / "version.json").read_text())
    browser_version(metadata)
    hashes = {}
    for name in ("version.json", "camoufox-bin", "libxul.so"):
        path = target / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError("missing or unsafe browser essential file: " + name)
        hashes[name] = file_hash(path)
    if not (target / "camoufox-bin").stat().st_mode & 0o111:
        raise ValueError("browser is not executable")
    with (target / "libxul.so").open("rb") as stream:
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as binary:
            if binary.find(b"_ERROR_FORMAT_BLOCK_SWITCH") < 0:
                raise ValueError("browser libxul lacks exact Brotli patch-marker evidence")
    return {"version": metadata["version"], "release": metadata["release"], "hashes": hashes,
            "libxul_marker": "_ERROR_FORMAT_BLOCK_SWITCH",
            "caveat": "Patch marker and release evidence are not full security clearance."}


class PublisherRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urlsplit(newurl)
        if url.scheme != "https" or url.hostname not in ("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"):
            raise ValueError("untrusted browser download redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_browser(url, output):
    opener = urllib.request.build_opener(PublisherRedirects())
    with opener.open(url, timeout=120) as response, output.open("xb") as stream:
        size = 0
        for block in iter(lambda: response.read(1024 * 1024), b""):
            size += len(block)
            if size > 2 * 1024 ** 3:
                raise ValueError("browser download exceeds size limit")
            stream.write(block)


def install_browser(policy, target, arch, fetch=fetch_browser):
    validate_policy(policy)
    target = Path(target)
    required = browser_version(policy["browser"])
    if target.is_symlink():
        raise ValueError("browser target must not be a symlink")
    if target.exists():
        metadata = json.loads((target / "version.json").read_text())
        current = browser_version(metadata)
        if current >= required:
            try:
                return dict(browser_evidence(target), action="keep")
            except ValueError as exc:
                raise ValueError("same/newer browser is unverified; refusing downgrade or replacement") from exc
    target.parent.mkdir(parents=True, exist_ok=True)
    artifact = policy["browser"]["artifacts"][arch]
    with tempfile.TemporaryDirectory(prefix="camofox-browser-", dir=target.parent) as tmp:
        archive, extracted = Path(tmp) / "browser.zip", Path(tmp) / "extracted"
        try:
            fetch(artifact["url"], archive)
        except (urllib.error.URLError, TimeoutError):
            if "mirror_url" not in artifact:
                raise
            archive.unlink(missing_ok=True)
            fetch(artifact["mirror_url"], archive)
        extract_browser(archive, extracted, artifact["sha256"])
        if not (extracted / "version.json").exists():
            (extracted / "version.json").write_text(json.dumps({k: policy["browser"][k] for k in ("version", "release")}))
        evidence = browser_evidence(extracted)
        if browser_version(evidence) != required:
            raise ValueError("downloaded browser version metadata disagrees with policy")
        if target.exists():
            try:
                target.rename(Path(tmp) / "old-browser")
            except OSError as exc:
                # The validated archive is already hash-checked and evidence-verified;
                # on Docker overlayfs a lower-layer directory rename can raise EXDEV.
                if exc.errno != errno.EXDEV:
                    raise
                shutil.rmtree(target)
        extracted.rename(target)
    return dict(evidence, action="replace", artifact=artifact)


def extract_browser(archive, destination, expected_hash):
    if file_hash(archive) != expected_hash:
        raise ValueError("browser SHA-256 mismatch before extraction")
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError("extraction destination must not exist")
    with zipfile.ZipFile(archive) as bundle:
        seen = set()
        total = 0
        for member in bundle.infolist():
            name = member.filename
            parts = name.rstrip("/").split("/")
            mode = member.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if (not name or "\\" in name or "\x00" in name or name.startswith("/")
                    or any(p in ("", ".", "..") for p in parts)
                    or name.rstrip("/") in seen or member.flag_bits & 1
                    or kind not in (0, stat.S_IFREG, stat.S_IFDIR)
                    or mode & 0o7000):
                raise ValueError("unsafe browser ZIP member: " + repr(name))
            seen.add(name.rstrip("/"))
            total += member.file_size
            if total > 4 * 1024 ** 3 or len(seen) > 100000:
                raise ValueError("browser ZIP exceeds extraction limits")
        if not {"camoufox-bin", "libxul.so"}.issubset(seen):
            raise ValueError("browser ZIP missing essential files")
        # Validate the entire member graph before touching the filesystem.
        directories = {m.filename.rstrip("/") for m in bundle.infolist() if m.is_dir()}
        for name in seen:
            parent = Path(name).parent
            while str(parent) != ".":
                if str(parent) in seen and str(parent) not in directories:
                    raise ValueError("ZIP file/directory conflict")
                parent = parent.parent
        destination.mkdir(mode=0o755)
        try:
            for member in bundle.infolist():
                path = destination / member.filename
                if member.is_dir():
                    path.mkdir(parents=True, exist_ok=True)
                    continue
                path.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member) as source, path.open("xb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                mode = (member.external_attr >> 16) & 0o777
                path.chmod(mode or 0o644)
            for name in ("camoufox-bin", "libxul.so"):
                path = destination / name
                if not path.is_file() or path.stat().st_size == 0:
                    raise ValueError("missing/empty browser essential file: " + name)
            if not (destination / "camoufox-bin").stat().st_mode & 0o111:
                raise ValueError("browser executable mode missing")
        except BaseException:
            shutil.rmtree(destination)
            raise


def browser_version(metadata):
    version, release = metadata.get("version"), metadata.get("release")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("unsupported browser version metadata")
    if not isinstance(release, str) or not re.fullmatch(r"beta\.\d+", release):
        raise ValueError("unsupported browser release comparison; expected beta.N")
    return (*map(int, version.split(".")), int(release.split(".")[1]))


def validate_policy(policy):
    node_version(policy.get("node_minimum"))
    if node_version(policy["node_minimum"]) < (22, 23, 4):
        raise ValueError("Node policy cannot weaken the security floor")
    for field in ("python_package_minimum", "brotli_package_minimum"):
        if not isinstance(policy.get(field), str) or not re.fullmatch(r"[0-9][0-9A-Za-z.+:~\-]*", policy[field]):
            raise ValueError("invalid Debian package policy: " + field)
    browser = policy["browser"]
    browser_version(browser)
    if set(browser["artifacts"]) != {"amd64", "arm64"}:
        raise ValueError("browser policy must cover exactly amd64 and arm64")
    for arch, artifact in browser["artifacts"].items():
        if not re.fullmatch(r"[a-f0-9]{64}", artifact.get("sha256", "")):
            raise ValueError("invalid browser SHA-256")
        url = urlsplit(artifact["url"])
        parts = url.path.split("/")
        tag = browser["version"] + "-" + browser["release"]
        cpu = "x86_64" if arch == "amd64" else "arm64"
        if (url.scheme != "https" or url.netloc != "github.com" or url.query or url.fragment
                or len(parts) != 7 or parts[1:5] != ["daijro", "camoufox", "releases", "download"]
                or parts[5] not in (tag, "v" + tag)):
            raise ValueError("untrusted browser publisher URL")
        expected = f"camoufox-{tag}-lin.{cpu}.zip"
        if parts[-1] != expected:
            raise ValueError("browser artifact name/version/architecture mismatch")
        if "mirror_url" in artifact:
            mirror = artifact["mirror_url"]
            if (tag != "152.0.4-beta.30" or mirror !=
                    "https://github.com/jo-inc/camofox-browser/releases/download/camoufox-backup-380139564/" + expected):
                raise ValueError("untrusted browser mirror release")
    return policy


def node_version(value):
    if not isinstance(value, str) or not re.fullmatch(r"v?22\.\d+\.\d+", value):
        raise ValueError("only stable compatible Node major 22 is supported: " + str(value))
    return tuple(map(int, value.lstrip("v").split(".")))


def select_node(current, candidate, minimum):
    floor = node_version(minimum)
    old = node_version(current["version"])
    new = node_version(candidate["version"])
    if new < floor or candidate.get("marker") != -17:
        raise ValueError("Node candidate below policy or missing exact Brotli patch marker")
    if old >= floor and current.get("marker") == -17:
        return "keep"
    if old > new:
        raise ValueError("unverified newer Node cannot be silently downgraded")
    return "replace"


def file_hash(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_snapshot(data):
    entries = data.get("entries", {})
    nonempty_files = {p for p, e in entries.items() if e.get("type") == "file" and e.get("size", 0) > 0}
    required = {"server.js", "package.json", "package-lock.json"}
    if not required.issubset(nonempty_files):
        raise ValueError("missing/empty application file coverage")
    for prefix in ("lib/", "plugins/", "mcp/", "scripts/", "node_modules/"):
        if not any(p.startswith(prefix) for p in nonempty_files):
            raise ValueError("missing/empty category coverage: " + prefix)
    if not any(p.startswith("node_modules/better-sqlite3/") and p.endswith(".node") for p in nonempty_files):
        raise ValueError("missing native better-sqlite3 addon coverage")
    if "node_modules/better-sqlite3/package.json" not in nonempty_files:
        raise ValueError("missing native dependency metadata coverage")


def snapshot(root=Path("/app")):
    root = Path(root)
    entries = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            info = path.lstat()
            entry: dict = {"mode": stat.S_IMODE(info.st_mode)}
            if stat.S_ISLNK(info.st_mode):
                entry.update(type="symlink", target=os.readlink(path))
            elif stat.S_ISREG(info.st_mode):
                entry.update(type="file", sha256=file_hash(path), size=info.st_size)
            elif stat.S_ISDIR(info.st_mode):
                entry.update(type="directory")
            else:
                raise ValueError("unexpected special application file: " + str(path))
            entries[path.relative_to(root).as_posix()] = entry
    data = {"schema": 1, "entries": entries}
    validate_snapshot(data)
    return data


def compare_snapshots(base, derived):
    validate_snapshot(base)
    validate_snapshot(derived)
    before, after = base["entries"], derived["entries"]
    return [p for p in sorted(before.keys() | after.keys()) if before.get(p) != after.get(p)]


def image_verifier():
    import importlib.util
    source = Path(__file__).resolve().parent / "verify_image.py"
    if not source.exists():
        source = source.parent / "tests" / "verify_image.py"
    spec = importlib.util.spec_from_file_location("camofox_verify_image", source)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def apply_overlay(policy, candidate, evidence_path, app_root=Path("/app")):
    validate_policy(policy)
    if os.geteuid() != 0:
        raise ValueError("overlay apply requires inherited root user; refusing to alter image USER")
    verifier = image_verifier()
    distro = verifier.distro_info()
    if distro.get("ID") != "debian" or distro.get("VERSION_CODENAME") != "trixie":
        raise ValueError("overlay apply only supports Debian trixie")
    before = snapshot(app_root)
    inventories = [verifier.python_inventory(path) for path in verifier.discover_interpreters()]
    for info in inventories:
        verifier.validate_python_inventory(info)
    arch = subprocess.run(["dpkg", "--print-architecture"], check=True, capture_output=True,
                          text=True, timeout=30).stdout.strip()
    if arch not in ("amd64", "arm64"):
        raise ValueError("unsupported browser architecture: " + arch)
    evidence = {"schema": 1, "architecture": arch, "python_metadata_before": inventories,
                "node": install_node(candidate, Path("/usr/local/bin/node"), policy["node_minimum"]),
                "browser": install_browser(policy, Path("/root/.cache/camoufox"), arch)}
    changes = compare_snapshots(before, snapshot(app_root))
    if changes:
        raise ValueError("overlay modified inherited /app: " + repr(changes))
    evidence["security"] = verifier.verify(policy, expected=evidence)
    changes = compare_snapshots(before, snapshot(app_root))
    if changes:
        raise ValueError("verification modified inherited /app: " + repr(changes))
    evidence["preservation"] = {"changed_paths": [], "entries": len(before["entries"]),
                                "snapshot_sha256": hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest()}
    path = Path(evidence_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    return evidence


def main():
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--snapshot-only", action="store_true")
    actions.add_argument("--compare-snapshots", nargs=2, metavar=("BASE", "DERIVED"))
    actions.add_argument("--apply", action="store_true")
    parser.add_argument("--node-candidate", type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--app-root", default="/app", help="read-only snapshot root")
    args = parser.parse_args()
    try:
        if args.snapshot_only:
            print(json.dumps(snapshot(Path(args.app_root)), sort_keys=True))
            return 0
        if args.apply:
            if args.node_candidate is None or args.policy is None or args.app_root != "/app":
                parser.error("--apply requires --node-candidate and --policy and fixed /app root")
            policy = json.loads(args.policy.read_text())
            evidence = apply_overlay(policy, args.node_candidate, Path("/usr/local/share/camofox-overlay/evidence.json"))
            print(json.dumps(evidence, sort_keys=True))
            return 0
        changes = compare_snapshots(*(json.loads(Path(p).read_text()) for p in args.compare_snapshots))
        print(json.dumps({"changed_paths": changes}, sort_keys=True))
        return 1 if changes else 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print("camofox overlay: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
