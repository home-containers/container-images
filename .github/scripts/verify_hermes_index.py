"""Validate the registry index descriptor returned by buildx imagetools inspect."""
import json
import re
import sys


def verify_index(index: dict) -> str:
    allowed_types = {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
    if index.get("schemaVersion") != 2 or index.get("mediaType") not in allowed_types:
        raise ValueError("Expected a schema-2 multiarchitecture registry index")
    manifests = index.get("manifests", [])
    platforms = {(item.get("platform", {}).get("os"), item.get("platform", {}).get("architecture")) for item in manifests}
    if len(manifests) != 2 or platforms != {("linux", "arm64"), ("linux", "amd64")}:
        raise ValueError("Index must contain exactly Linux ARM64 and AMD64")
    digests = [index.get("digest", "")] + [item.get("digest", "") for item in manifests]
    if any(not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) for digest in digests):
        raise ValueError("Invalid registry descriptor digest")
    return index["digest"]


if __name__ == "__main__":
    print(verify_index(json.load(sys.stdin)))
