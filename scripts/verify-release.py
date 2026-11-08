#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile


def digest(path):
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def members(archive):
    result = archive.getmembers()
    for member in result:
        path = PurePosixPath(member.name)
        assert not path.is_absolute() and ".." not in path.parts
        assert member.isfile() or member.isdir(), "Release contains a link or special file"
        assert not {".git", ".codex", "target", "evidence"}.intersection(path.parts)
        assert path.name not in {"auth.json", "credentials.json", "ai.local.toml"}
        assert not path.name.startswith(".env")
    assert len({member.name for member in result}) == len(result), "Duplicate archive member"
    return result


def run(binary, *arguments, expected=0):
    result = subprocess.run([str(binary), *arguments], capture_output=True, timeout=30)
    assert result.returncode == expected, result.stderr.decode(errors="replace")
    return result.stdout


directory = Path(sys.argv[1]).resolve()
checksums = (directory / "SHA256SUMS").read_text().splitlines()
assets = set()
for line in checksums:
    match = re.fullmatch(r"([0-9a-f]{64}) [ *]([A-Za-z0-9_.+-]+\.tar\.gz)", line)
    assert match, "Invalid checksum entry"
    checksum, name = match.groups()
    assert name not in assets, "Repeated checksum entry"
    assets.add(name)
    assert digest(directory / name) == checksum, "Release checksum mismatch"
assert len(assets) == 2
assert {entry.name for entry in directory.iterdir()} == assets | {"SHA256SUMS"}
source = next(directory.glob("*-source.tar.gz"))
bundle = next(directory.glob("*-x86_64-unknown-linux-gnu.tar.gz"))
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
tracked = set(subprocess.check_output(["git", "ls-tree", "-rz", "--name-only", "HEAD"]).decode().rstrip("\0").split("\0"))
with tarfile.open(source) as archive:
    source_members = members(archive)
    assert archive.pax_headers.get("comment") == commit
    source_files = {"/".join(PurePosixPath(item.name).parts[1:]) for item in source_members if item.isfile()}
    assert source_files == tracked, "Source release differs from the committed tree"
with tempfile.TemporaryDirectory(prefix="aurlens-release-check-") as scratch:
    with tarfile.open(bundle) as archive:
        bundle_members = members(archive)
        roots = {PurePosixPath(item.name).parts[0] for item in bundle_members}
        assert len(roots) == 1
        root = roots.pop()
        bundle_files = {"/".join(PurePosixPath(item.name).parts[1:]) for item in bundle_members if item.isfile()}
        assert bundle_files == tracked | {"bin/aurlens", "release.json"}
        archive.extractall(scratch)
    installed = Path(scratch) / root / "bin/aurlens"
    metadata = json.loads((Path(scratch) / root / "release.json").read_text())
    assert metadata["source_commit"] == commit
    assert metadata["target"] == "x86_64-unknown-linux-gnu"
    assert metadata["binary_sha256"] == digest(installed)
    assert os.stat(installed).st_mode & 0o777 == 0o755
    header = installed.read_bytes()[:20]
    assert header[:6] == b"\x7fELF\x02\x01" and int.from_bytes(header[18:20], "little") == 62
    symbols = subprocess.check_output(["readelf", "--version-info", str(installed)])
    glibc_versions = [tuple(map(int, version.split(b"."))) for version in re.findall(rb"GLIBC_([0-9.]+)", symbols)]
    assert glibc_versions and max(glibc_versions) <= (2, 35), "Binary needs a newer glibc than the supported minimum"
    assert run(installed, "--version").decode().strip() == "aurlens " + metadata["version"]
    run(installed, "setup", "--help")
    recipe = Path(scratch) / "recipe"
    recipe.mkdir()
    marker = Path(scratch) / "must-not-exist"
    (recipe / "PKGBUILD").write_text("pkgname=release-check\ntouch " + shlex.quote(str(marker)) + "\n")
    report = json.loads(run(installed, "scan", str(recipe), "--no-ai", "--json"))
    assert report["coverage"]["complete"] and report["revalidated"]
    assert report["ai"]["state"] == "not_run" and not marker.exists()
    matched = json.loads(run(installed, "verify", str(recipe), "--snapshot-digest", report["snapshot_digest"], "--json"))
    assert matched["status"] == "matched"
    (recipe / "PKGBUILD").write_text("pkgname=changed\n")
    changed = json.loads(run(installed, "verify", str(recipe), "--snapshot-digest", report["snapshot_digest"], "--json", expected=3))
    assert changed["status"] == "changed" and not marker.exists()
print("Release checksums, committed contents, installed CLI, and snapshot checks passed.")
