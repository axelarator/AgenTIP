#!/usr/bin/env python3
"""Static triage of files pulled from an open directory.

Runs INSIDE the container, on the probe VM. Reads a directory of samples,
writes one JSON document to stdout. Nothing here executes a sample, opens
a socket, or writes outside /tmp.

The output is the only thing that leaves: the cti host receives these
verdicts over SSH and stores them in DuckDB. No sample byte ever reaches
the analyst's machine or the repository, which is the whole reason the
container is on the VM that did the download rather than here.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

MAX_READ = 8 * 1024 * 1024        # per file; a bigger sample is hashed, not parsed
MAX_STRINGS = 60
MIN_STRING_LEN = 6

_PRINTABLE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)
_URL = re.compile(rb"https?://[^\s\"'<>\\]{4,200}")
_IPV4 = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(rb"\b(?:[a-z0-9-]{1,63}\.){1,4}[a-z]{2,18}\b", re.I)
_B64_BLOB = re.compile(rb"[A-Za-z0-9+/]{120,}={0,2}")

# Extension -> the magic prefix it claims. A mismatch is itself a finding:
# a .txt that starts with MZ is not a text file.
_MAGIC = {
    b"MZ": "PE executable",
    b"\x7fELF": "ELF executable",
    b"PK\x03\x04": "zip archive",
    b"\x1f\x8b": "gzip",
    b"Rar!": "rar archive",
    b"%PDF": "PDF",
    b"\xff\xd8\xff": "JPEG",
    b"\x89PNG": "PNG",
    b"7z\xbc\xaf": "7-zip",
    b"\xfd7zXZ": "xz",
    b"BZh": "bzip2",
    b"SQLite format 3": "SQLite database",
}

# Extensions that imply human-readable content. A file with one of these
# whose bytes are a known binary format is the interesting mismatch - and
# the one the first version missed, because it only compared extensions it
# had an expected type for. "cmd5.txt" that is really a PE is exactly the
# thing an open directory hides.
_TEXTUAL_EXTS = {".txt", ".log", ".md", ".cfg", ".conf", ".ini", ".json",
                 ".csv", ".yml", ".yaml", ".xml", ".html", ".htm", ".sh",
                 ".bat", ".ps1", ".py", ".php", ".js", ".sql", ".list", ""}

_BINARY_TYPES = {"PE executable", "ELF executable", "zip archive", "gzip",
                 "rar archive", "7-zip", "xz", "bzip2", "SQLite database"}

_EXPECTED_BY_EXT = {
    ".exe": "PE executable", ".dll": "PE executable", ".sys": "PE executable",
    ".zip": "zip archive", ".gz": "gzip", ".tgz": "gzip", ".rar": "rar archive",
    ".pdf": "PDF", ".jpg": "JPEG", ".jpeg": "JPEG", ".png": "PNG",
    ".7z": "7-zip", ".xz": "xz", ".bz2": "bzip2", ".db": "SQLite database",
    ".sqlite": "SQLite database",
}


def _sniff(head: bytes) -> str | None:
    for prefix, name in _MAGIC.items():
        if head.startswith(prefix):
            return name
    return None


def _libmagic(path: Path) -> str | None:
    try:
        import magic
        return magic.from_file(str(path))
    except Exception:
        return None


def _mime(path: Path) -> str | None:
    try:
        import magic
        return magic.from_file(str(path), mime=True)
    except Exception:
        return None


def _yara_hits(path: Path, rules) -> list[dict]:
    if rules is None:
        return []
    try:
        matches = rules.match(str(path), timeout=20)
    except Exception as e:
        return [{"rule": "_yara_error", "description": str(e), "severity": "unknown"}]
    out = []
    for m in matches:
        meta = getattr(m, "meta", {}) or {}
        out.append({"rule": m.rule,
                    "description": meta.get("description"),
                    "severity": meta.get("severity", "unknown")})
    return out


def _strings(blob: bytes) -> list[str]:
    seen, out = set(), []
    for match in _PRINTABLE.findall(blob):
        text = match.decode("ascii", "replace")
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= MAX_STRINGS:
            break
    return out


def _extracted(blob: bytes) -> dict:
    def decode(values, limit=25):
        seen, out = set(), []
        for v in values:
            text = v.decode("ascii", "replace")
            if text not in seen:
                seen.add(text)
                out.append(text)
            if len(out) >= limit:
                break
        return out

    return {
        "urls": decode(_URL.findall(blob)),
        "ipv4": decode(_IPV4.findall(blob)),
        "domains": decode(_DOMAIN.findall(blob)),
        "base64_blobs": len(_B64_BLOB.findall(blob)),
    }


def _verdict(result: dict) -> str:
    """A one-word triage label, so the opendir specialist can sort thirty
    files without reading thirty records."""
    severities = {h.get("severity") for h in result["yara_hits"]}
    if "high" in severities:
        return "notable"
    if result.get("type_mismatch"):
        return "notable"
    if "medium" in severities:
        return "interesting"
    if result["extracted"]["urls"] or result["extracted"]["ipv4"]:
        return "interesting"
    return "unremarkable"


def _mismatched(path: Path, sniffed: str | None, expected: str | None) -> bool:
    if sniffed is None:
        return False
    if expected:
        return expected != sniffed
    return path.suffix.lower() in _TEXTUAL_EXTS and sniffed in _BINARY_TYPES


def analyze(path: Path, rules) -> dict:
    size = path.stat().st_size
    sha256 = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            sha256.update(block)

    with path.open("rb") as fh:
        blob = fh.read(MAX_READ)

    sniffed = _sniff(blob[:32])
    expected = _EXPECTED_BY_EXT.get(path.suffix.lower())
    result = {
        "path": path.name,
        "size": size,
        "sha256": sha256.hexdigest(),
        "magic": _libmagic(path) or sniffed,
        "mime": _mime(path),
        "sniffed": sniffed,
        "truncated_at": MAX_READ if size > MAX_READ else None,
        # A file whose contents contradict its extension is worth saying
        # out loud - it is the cheapest lie to tell and a common one.
        "type_mismatch": _mismatched(path, sniffed, expected),
        "yara_hits": _yara_hits(path, rules),
        "strings_sample": _strings(blob),
        "extracted": _extracted(blob),
    }
    result["verdict"] = _verdict(result)
    return result


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/in")
    rules = None
    rules_path = Path("/opt/rules")
    if rules_path.is_dir():
        try:
            import yara
            rules = yara.compile(filepaths={
                p.stem: str(p) for p in sorted(rules_path.glob("*.yar"))})
        except Exception as e:
            print(json.dumps({"error": f"yara rules failed to compile: {e}"}))
            return 1

    results, errors = [], []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            results.append(analyze(path, rules))
        except Exception as e:                  # one bad file must not
            errors.append({"path": path.name,   # lose the other twenty-nine
                           "error": f"{type(e).__name__}: {e}"})

    json.dump({"results": results, "errors": errors,
               "analyzed": len(results)}, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
