"""Read-only checks for the derived Hermes image; also detects the unpatched base."""
from __future__ import annotations

import ctypes
import ctypes.util
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    report: dict = {"python": sys.version.split()[0], "executable": sys.executable}
    try:
        require(sys.version_info >= (3, 14, 9), "managed Python must be at least 3.14.9")
        # Check metadata BEFORE importing a potentially affected decoder.
        version = importlib.metadata.version("brotlicffi")
        report["brotlicffi"] = version
        require(tuple(map(int, version.split("."))) >= (1, 2, 1, 0),
                f"affected Python decoder: brotlicffi {version}")
        try:
            alternate = importlib.metadata.version("Brotli")
        except importlib.metadata.PackageNotFoundError:
            alternate = None
        if alternate is not None:
            require(tuple(map(int, alternate.split("."))) >= (1, 2, 1),
                    f"affected alternate Python decoder: Brotli {alternate}")
        report["Brotli"] = alternate
        distro_version = subprocess.check_output(
            ["dpkg-query", "-W", "-f=${Version}", "libbrotli1"], text=True).strip()
        report["libbrotli1"] = distro_version
        require(subprocess.run(["dpkg", "--compare-versions", distro_version, "ge",
                                "1.1.0-2+deb13u1"], check=False).returncode == 0,
                "Debian Brotli security backport is missing")
        decoder = ctypes.CDLL(ctypes.util.find_library("brotlidec") or "libbrotlidec.so.1")
        decoder.BrotliDecoderErrorString.argtypes = [ctypes.c_int]
        decoder.BrotliDecoderErrorString.restype = ctypes.c_char_p
        marker = decoder.BrotliDecoderErrorString(-17)
        report["native_decoder_error_minus17"] = marker.decode() if marker else None
        require(marker == b"FORMAT_BLOCK_SWITCH", "native decoder patch marker is missing")
        node = json.loads(subprocess.check_output([
            "/usr/local/bin/node", "-p",
            'JSON.stringify({version:process.version,error:require("node:zlib").constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH})',
        ], text=True))
        report["node"] = node
        require(node.get("error") == -17, "Node bundled Brotli patch marker is missing")
        import brotlicffi
        from httpx._decoders import BrotliDecoder
        payload = b"container-images: controlled Brotli round-trip\n" * 8
        compressed = brotlicffi.compress(payload)
        require(brotlicffi.decompress(compressed) == payload, "Python Brotli round-trip failed")
        http_decoder = BrotliDecoder()
        require(http_decoder.decode(compressed) + http_decoder.flush() == payload,
                "HTTPX Brotli decoding failed")
        report["brotli_roundtrip"] = "passed"
        report["httpx_decoder"] = "passed"
        # This is an inspection API, not an installer. Do not repair during verification.
        root = Path("/opt/hermes")
        sys.path.insert(0, str(root))
        from pm.install import drift
        report["pm_drift"] = drift()
        require(not report["pm_drift"], "managed dependencies are out of sync with their locks")
        report["status"] = "passed"
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = str(exc)
        print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
