#!/usr/bin/env python3
"""Offline image security checks. Patch markers are not full security clearance."""
import importlib.metadata
from pathlib import Path
import re
import subprocess
import ctypes
import ctypes.util
import importlib.util
import json
import os
import sys
import sysconfig

NODE_CHECK = r"""
const z = require('node:zlib');
const marker = z.constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH;
if (marker !== -17) throw new Error('Node lacks exact Brotli patch marker');
const data = Buffer.from('camofox-overlay-brotli-roundtrip');
if (!z.brotliDecompressSync(z.brotliCompressSync(data)).equals(data)) throw new Error('Brotli roundtrip failed');
console.log(JSON.stringify({version: process.versions.node, brotli: process.versions.brotli, marker}));
"""
SQLITE_CHECK = r"""
const Database = require('better-sqlite3');
const db = new Database(':memory:');
db.exec('CREATE TABLE overlay_check (value INTEGER)');
db.prepare('INSERT INTO overlay_check VALUES (?)').run(42);
if (db.prepare('SELECT value FROM overlay_check').get().value !== 42) throw new Error('sqlite native addon failed');
db.close(); console.log(JSON.stringify({better_sqlite3: 'in-memory roundtrip passed'}));
"""


def command(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=120,
                          env={k: v for k, v in os.environ.items()
                               if k not in ("NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "PYTHONHOME")}, **kwargs).stdout


def overlay_module():
    here = Path(__file__).resolve().parent
    source = here / "build_overlay.py"
    if not source.exists():
        source = here.parent / "build_overlay.py"
    spec = importlib.util.spec_from_file_location("camofox_build_overlay", source)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def python_site_paths():
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    # On Python <=3.13 -S suppresses venv prefix setup; inspect cfg, never execute site.
    prefix = Path(sys.executable).parent.parent
    cfg = prefix / "pyvenv.cfg"
    if cfg.is_file():
        sites = {str(prefix / "lib" / version / "site-packages")}
        include_system = bool(re.search(r"(?im)^include-system-site-packages\s*=\s*true\s*$", cfg.read_text()))
    else:
        paths = sysconfig.get_paths()
        sites = {paths["purelib"], paths["platlib"]}
        include_system = True
    if include_system:
        sites.update(("/usr/lib/python3/dist-packages", "/usr/local/lib/python3/dist-packages",
                      f"/usr/local/lib/{version}/dist-packages", f"/usr/local/lib/{version}/site-packages"))
    return sorted(str(Path(p)) for p in sites if Path(p).is_dir())


def python_inventory(executable):
    return json.loads(command([str(executable), "-B", "-I", "-S", str(Path(__file__).resolve()), "--python-inventory"]))


def local_python_inventory():
    sites = python_site_paths()
    rows = metadata_inventory(sites)
    modules = []
    for site in sites:
        for pattern in ("*brotli*", "*Brotli*"):
            for path in Path(site).glob(pattern):
                if path.name.endswith((".dist-info", ".egg-info")):
                    continue
                modules.append(str(path))
    return {"executable": sys.executable, "prefix": sys.prefix, "base_prefix": sys.base_prefix,
            "runtime_version": ".".join(map(str, sys.version_info[:3])),
            "sysconfig": sysconfig.get_paths(), "sites": sites,
            "distributions": rows, "binding_module_paths": sorted(set(modules))}


def validate_python_inventory(info):
    validate_bindings(info["distributions"])
    installed = {re.sub(r"[-_.]+", "-", row["name"]).lower() for row in info["distributions"]}
    for path in info["binding_module_paths"]:
        name = Path(path).name.lower()
        owner = "brotlicffi" if "brotlicffi" in name else "brotli"
        if owner not in installed:
            raise ValueError("unowned Python binding requires separate ownership-aware override: " + path)


def discover_interpreters():
    found = set()
    for base in (Path("/usr/bin"), Path("/usr/local"), Path("/opt"), Path("/root"), Path("/app")):
        if not base.exists():
            continue
        for directory, dirs, files in os.walk(base, followlinks=False):
            dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", ".cache")]
            for name in files:
                if re.fullmatch(r"python(?:3(?:\.\d+)?)?", name):
                    path = Path(directory) / name
                    if os.access(path, os.X_OK) and path.is_file():
                        found.add(str(path))
    if "/usr/bin/python3" not in found:
        raise ValueError("system Python interpreter missing")
    return sorted(found)


def binding_roundtrips(info):
    validate_python_inventory(info)
    # Only after metadata for every interpreter passes may extension modules execute.
    code = "import sys; sys.path.extend(" + repr(info["sites"]) + "); "
    names = {row["name"].lower() for row in info["distributions"]}
    checks = []
    for name in ("brotli", "brotlicffi"):
        if name in names:
            checks.append(f"import {name} as b; assert b.decompress(b.compress(b'overlay-roundtrip')) == b'overlay-roundtrip'")
    if checks:
        command([info["executable"], "-B", "-I", "-S", "-c", code + "; ".join(checks)])


BINDING_FLOORS = {"brotli": (1, 2, 1), "brotlicffi": (1, 2, 1, 0)}


def metadata_inventory(paths):
    return sorted(({"name": d.metadata.get("Name", ""), "version": d.version,
                    "location": str(d.locate_file(""))}
                   for d in importlib.metadata.distributions(path=[str(p) for p in paths])),
                  key=lambda row: (row["name"].lower(), row["location"]))


def validate_bindings(rows):
    for row in rows:
        name = re.sub(r"[-_.]+", "-", row["name"]).lower()
        if "brotli" not in name:
            continue
        version = row["version"]
        if (name not in BINDING_FLOORS or not re.fullmatch(r"\d+(?:\.\d+)*", version)
                or tuple(map(int, version.split("."))) < BINDING_FLOORS[name]):
            raise ValueError("Python binding requires separate ownership-aware override: " + repr(row))


def validate_system_marker(value):
    if value != b"_ERROR_FORMAT_BLOCK_SWITCH":
        raise ValueError("system Brotli lacks exact _ERROR_FORMAT_BLOCK_SWITCH marker: " + repr(value))


def debian_ge(version, minimum):
    result = subprocess.run(["dpkg", "--compare-versions", version, "ge", minimum], check=False)
    if result.returncode not in (0, 1):
        raise ValueError("invalid Debian version comparison")
    return result.returncode == 0


def validate_package_set(policy, packages, runtime):
    names = ("python3.13", "python3.13-minimal", "libpython3.13-stdlib", "libpython3.13-minimal")
    versions = [packages.get(name) for name in names]
    if any(v is None for v in versions) or len(set(versions)) != 1:
        raise ValueError("Python interpreter/std lib Debian package versions disagree")
    version = packages["python3.13"]
    if not debian_ge(version, policy["python_package_minimum"]):
        raise ValueError("Debian Python package below required backport")
    upstream = version.split(":")[-1].split("-")[0]
    if runtime != upstream or not runtime.startswith("3.13."):
        raise ValueError("Python runtime does not match distro-owned interpreter/std lib package set")
    if not debian_ge(packages.get("libbrotli1", "0"), policy["brotli_package_minimum"]):
        raise ValueError("Debian libbrotli1 below required backport")


def installed_packages():
    names = ("python3.13", "python3.13-minimal", "libpython3.13-stdlib", "libpython3.13-minimal", "libbrotli1")
    packages = {}
    for name in names:
        line = command(["dpkg-query", "-W", "-f=${db:Status-Status}\\t${Version}\\n", name]).strip()
        state, version = line.split("\t")
        if state != "installed":
            raise ValueError("required package is not installed: " + name)
        packages[name] = version
    return packages


def distro_info():
    values = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip('"')
    return values


def system_brotli_marker():
    name = ctypes.util.find_library("brotlidec")
    if not name:
        raise ValueError("system Brotli decoder shared library missing")
    library = ctypes.CDLL(name)
    library.BrotliDecoderErrorString.argtypes = [ctypes.c_int]
    library.BrotliDecoderErrorString.restype = ctypes.c_char_p
    return library.BrotliDecoderErrorString(-17)


def verify(policy, expected=None):
    helper = overlay_module()
    helper.validate_policy(policy)
    distro = distro_info()
    if distro.get("ID") != "debian" or distro.get("VERSION_CODENAME") != "trixie":
        raise ValueError("only Debian trixie image is supported")
    packages = installed_packages()
    inventories = [python_inventory(path) for path in discover_interpreters()]
    for info in inventories:
        validate_python_inventory(info)
        # Alternative unmanaged interpreters need their own reviewed security policy.
        if (not info["runtime_version"].startswith("3.13.")
                or Path(info["executable"]).resolve() != Path("/usr/bin/python3").resolve()):
            raise ValueError("additional Python runtime requires separate ownership-aware override: " + info["executable"])
    system = next(i for i in inventories if i["executable"] == "/usr/bin/python3")
    validate_package_set(policy, packages, system["runtime_version"])
    marker = system_brotli_marker()
    validate_system_marker(marker)
    node = json.loads(command(["/usr/local/bin/node", "-e", NODE_CHECK]))
    if helper.node_version(node["version"]) < helper.node_version(policy["node_minimum"]) or node.get("marker") != -17:
        raise ValueError("Node runtime below policy or missing exact Brotli patch marker")
    sqlite = json.loads(command(["/usr/local/bin/node", "-e", SQLITE_CHECK], cwd="/app"))
    browser = helper.browser_evidence(Path("/root/.cache/camoufox"))
    if helper.browser_version(browser) < helper.browser_version(policy["browser"]):
        raise ValueError("browser runtime is below required release")
    if expected is not None:
        if (helper.file_hash("/usr/local/bin/node") != expected["node"]["sha256"]
                or browser["hashes"] != expected["browser"]["hashes"]):
            raise ValueError("installed runtime hashes differ from overlay evidence")
    for info in inventories:
        binding_roundtrips(info)
    return {"distro": distro, "packages": packages, "python": inventories, "node": node,
            "sqlite": sqlite, "system_brotli_marker": marker.decode("ascii"), "browser": browser,
            "caveat": "Component-specific backport, release and marker evidence; not full security clearance."}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python-inventory", action="store_true")
    parser.add_argument("--policy", default="/usr/local/share/camofox-overlay/policy.json")
    parser.add_argument("--evidence", default="/usr/local/share/camofox-overlay/evidence.json")
    args = parser.parse_args()
    try:
        if args.python_inventory:
            result = local_python_inventory()
        else:
            result = verify(json.loads(Path(args.policy).read_text()), json.loads(Path(args.evidence).read_text()))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, StopIteration, subprocess.SubprocessError) as exc:
        print("camofox image verification: " + str(exc), file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            print(exc.stderr, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
