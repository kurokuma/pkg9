#!/usr/bin/env python3
"""Download npm package tarballs listed in npm_mal_list.txt into ./dl.

This script downloads and unpacks tarballs without installing dependencies
or executing any package lifecycle hooks.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tarfile
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


REGISTRY_BASE = "https://registry.npmjs.org"
DEFAULT_LIST = "npm_mal_list.txt"
DEFAULT_OUT = "dl"
USER_AGENT = "pkg9-mal-package-downloader/1.0"


def normalize_spec(raw: str) -> str:
    text = raw.strip()
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def parse_spec(spec: str) -> tuple[str, str]:
    if not spec:
        raise ValueError("empty package spec")
    if spec.startswith("@"):
        slash = spec.find("/")
        if slash == -1:
            raise ValueError(f"invalid scoped package spec: {spec}")
        at = spec.rfind("@")
        if at <= slash:
            raise ValueError(f"missing version in package spec: {spec}")
        return spec[:at], spec[at + 1 :]
    name, sep, version = spec.rpartition("@")
    if not sep or not name or not version:
        raise ValueError(f"invalid package spec: {spec}")
    return name, version


def registry_url(name: str, version: str) -> str:
    quoted_name = urllib.parse.quote(name, safe="@")
    quoted_version = urllib.parse.quote(version, safe="")
    return f"{REGISTRY_BASE}/{quoted_name}/{quoted_version}"


def tarball_name(name: str, version: str) -> str:
    safe_name = name.replace("/", "__").replace("@", "")
    return f"{safe_name}-{version}.tgz"


def package_dir_name(name: str, version: str) -> str:
    safe_name = name.replace("/", "__").replace("@", "")
    return f"{safe_name}_{version}"


def fetch_json(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def download_file(url: str, dest: Path, timeout: float) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        with dest.open("wb") as fh:
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                fh.write(chunk)


def load_specs(list_path: Path) -> list[str]:
    specs: list[str] = []
    for line in list_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        specs.append(normalize_spec(line))
    return specs


def is_within_directory(base: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def extract_tarball(tarball_path: Path, dest_dir: Path) -> None:
    with tarfile.open(tarball_path, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            member_path = dest_dir / member.name
            if not is_within_directory(dest_dir, member_path):
                raise ValueError(f"unsafe archive path: {member.name}")
        archive.extractall(dest_dir)


def find_existing_tarball(out_dir: Path, filename: str) -> Path | None:
    for path in out_dir.rglob(filename):
        if path.is_file():
            return path
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download npm package tarballs listed as package@version."
    )
    parser.add_argument(
        "--list",
        default=DEFAULT_LIST,
        help="path to the package list file",
    )
    parser.add_argument(
        "--out-dir",
        default=DEFAULT_OUT,
        help="directory to store downloaded tarballs",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="HTTP timeout in seconds",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="overwrite existing tarballs",
    )
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    list_path = (base_dir / args.list).resolve() if not os.path.isabs(args.list) else Path(args.list)
    out_dir = (base_dir / args.out_dir).resolve() if not os.path.isabs(args.out_dir) else Path(args.out_dir)

    if not list_path.exists():
        print(f"list file not found: {list_path}", file=sys.stderr)
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)
    specs = load_specs(list_path)
    if not specs:
        print("no package specs found", file=sys.stderr)
        return 1

    success = 0
    skipped = 0
    failed = 0

    for spec in specs:
        try:
            name, version = parse_spec(spec)
            metadata = fetch_json(registry_url(name, version), args.timeout)
            tarball_url = metadata["dist"]["tarball"]
            package_dir = out_dir / package_dir_name(name, version)
            tarball_filename = tarball_name(name, version)
            tarball_path = package_dir / tarball_filename
            extracted_marker = package_dir / "package"
            existing_tarball = find_existing_tarball(out_dir, tarball_filename)
            if existing_tarball is not None and not args.overwrite:
                print(f"SKIP {spec} -> existing {existing_tarball.relative_to(out_dir)}")
                skipped += 1
                continue
            if package_dir.exists() and extracted_marker.exists() and not args.overwrite:
                print(f"SKIP {spec} -> {package_dir.name}")
                skipped += 1
                continue
            if package_dir.exists() and args.overwrite:
                for child in sorted(package_dir.rglob("*"), reverse=True):
                    if child.is_file() or child.is_symlink():
                        child.unlink()
                    elif child.is_dir():
                        child.rmdir()
                package_dir.rmdir()
            package_dir.mkdir(parents=True, exist_ok=True)
            download_file(tarball_url, tarball_path, args.timeout)
            extract_tarball(tarball_path, package_dir)
            print(f"OK   {spec} -> {package_dir.name}")
            success += 1
        except (KeyError, ValueError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            print(f"FAIL {spec} -> {exc}", file=sys.stderr)
            failed += 1

    print(
        json.dumps(
            {
                "total": len(specs),
                "downloaded": success,
                "skipped": skipped,
                "failed": failed,
                "output_dir": str(out_dir),
            },
            ensure_ascii=False,
        )
    )
    return 0 if failed == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
