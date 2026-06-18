#!/usr/bin/env python3
"""Rewrite a generated Homebrew cask to use release checksums."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


SHA_RE = re.compile(r'^(?P<indent>\s*)sha256 "[0-9a-f]{64}"\s*$')
URL_RE = re.compile(
    r'^\s*url "https://github\.com/daxchain-io/daxie/releases/download/'
    r'v#\{version\}/daxie_#\{version\}_(?P<suffix>[^"]+)"\s*$'
)

REQUIRED_SUFFIXES = {
    "darwin_amd64.tar.gz",
    "darwin_arm64.tar.gz",
    "linux_amd64.tar.gz",
    "linux_arm64.tar.gz",
}


def release_version(raw: str) -> str:
    version = raw.strip()
    if version.startswith("v"):
        version = version[1:]
    if not version:
        raise ValueError("version must not be empty")
    return version


def read_checksums(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2:
            raise ValueError(f"{path}:{line_number}: expected '<sha256> <filename>'")
        digest, filename = parts
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"{path}:{line_number}: invalid sha256 {digest!r}")
        checksums[filename] = digest
    return checksums


def rewrite(cask_path: Path, checksums: dict[str, str], version: str) -> tuple[str, list[str], bool]:
    lines = cask_path.read_text(encoding="utf-8").splitlines(keepends=True)
    found: list[str] = []
    changed = False

    for index, line in enumerate(lines):
        url_match = URL_RE.match(line.rstrip("\n"))
        if not url_match:
            continue

        suffix = url_match.group("suffix")
        filename = f"daxie_{version}_{suffix}"
        if suffix not in REQUIRED_SUFFIXES:
            continue
        if filename not in checksums:
            raise ValueError(f"{cask_path}: missing checksum entry for {filename}")

        sha_index = index - 1
        while sha_index >= 0 and not lines[sha_index].strip():
            sha_index -= 1
        if sha_index < 0:
            raise ValueError(f"{cask_path}: url for {filename} has no preceding sha256")

        sha_match = SHA_RE.match(lines[sha_index].rstrip("\n"))
        if not sha_match:
            raise ValueError(f"{cask_path}: url for {filename} is not preceded by a sha256 line")

        replacement = f'{sha_match.group("indent")}sha256 "{checksums[filename]}"\n'
        if lines[sha_index] != replacement:
            lines[sha_index] = replacement
            changed = True
        found.append(filename)

    required = {f"daxie_{version}_{suffix}" for suffix in REQUIRED_SUFFIXES}
    missing = sorted(required - set(found))
    if missing:
        raise ValueError(f"{cask_path}: missing cask URL entries for: {', '.join(missing)}")

    return "".join(lines), sorted(found), changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cask", required=True, type=Path)
    parser.add_argument("--checksums", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    try:
        version = release_version(args.version)
        checksums = read_checksums(args.checksums)
        content, filenames, changed = rewrite(args.cask, checksums, version)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.check:
        if changed:
            print(f"error: {args.cask} does not match release checksums", file=sys.stderr)
            return 1
    else:
        args.cask.write_text(content, encoding="utf-8")

    print(f"verified cask checksums for {', '.join(filenames)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
