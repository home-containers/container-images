#!/usr/bin/env python3
"""Stdlib-only initial browser installer for the pinned upstream source build.

The legacy filename is retained for the CI staging contract; no image, Node,
application, or existing-browser mutation is supported.
"""
import hashlib
import json
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
    if target.exists() or target.is_symlink():
        raise ValueError("initial browser target must not exist")
    if arch not in policy["browser"]["artifacts"]:
        raise ValueError("unsupported browser architecture: " + str(arch))
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
        extracted.rename(target)
    return dict(evidence, action="install", artifact=artifact)


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
    if policy.get("source") != {
            "repository": "jo-inc/camofox-browser",
            "revision": "39c82094013480b373df6600d44c7f036f58356e",
            "release": "v1.18.1"}:
        raise ValueError("source policy must identify the reviewed upstream release and commit")
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


def file_hash(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-browser", required=True, action="store_true")
    parser.add_argument("--arch", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--policy", required=True, type=Path)
    args = parser.parse_args()
    try:
        policy = json.loads(args.policy.read_text())
        result = install_browser(policy, Path("/root/.cache/camoufox"), args.arch)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        print("camofox browser install: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
