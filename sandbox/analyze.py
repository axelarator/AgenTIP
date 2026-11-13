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
                 ".bat", ".ps1", ".py", ".php", ".js", ".sql", ".list"}
# No extension is not in that set. It was, on the idea that an unnamed file
# claims to be text - but Linux tools almost never carry an extension, so
# every ELF beacon and exploit in a directory came back as a type mismatch.

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


_STRING_POOL = 20_000          # unique strings considered before ranking
_PATHISH = re.compile(r"(?:^|[\s\"'=])(?:/|[A-Za-z]:\\|\./|~/)[\w.\-]+")
_WORDS = re.compile(r"[A-Za-z]{3,}")


def _string_score(text: str) -> float:
    """How much a string is worth showing an analyst. A stripped binary's
    first printable runs are instruction bytes (`UUUUUUUUH!`, `H(H+H0H`);
    the URLs, paths and messages come megabytes later."""
    score = min(len(text), 80) / 80
    if "://" in text or _IPV4.search(text.encode("ascii", "replace")):
        score += 3
    if _PATHISH.search(text):
        score += 2
    if " " in text and len(_WORDS.findall(text)) >= 2:
        score += 2
    if "%" in text or "error" in text.lower() or "fail" in text.lower():
        score += 1
    score += len(set(text)) / len(text)          # repeated characters score low
    return score


def _strings(blob: bytes) -> list[str]:
    """The MAX_STRINGS most informative printable strings, in file order."""
    seen: dict[str, int] = {}
    for match in _PRINTABLE.findall(blob):
        text = match.decode("ascii", "replace")
        if text not in seen:
            seen[text] = len(seen)
            if len(seen) >= _STRING_POOL:
                break
    best = sorted(seen, key=lambda t: (-_string_score(t), seen[t]))[:MAX_STRINGS]
    return sorted(best, key=seen.get)


def _load_tlds() -> frozenset[str]:
    for path in (Path(__file__).with_name("tlds.txt"), Path("/opt/tlds.txt")):
        try:
            return frozenset(line.strip() for line in path.read_text().splitlines()
                             if line.strip() and not line.startswith("#"))
        except OSError:
            continue
    return frozenset()


_TLDS = _load_tlds()
# Real top-level domains that, in the strings of a program, are nearly always
# a file extension or a method name: libcrypto.so, loader.py, time.now,
# sync.map, os.open. A real domain on one of these is still found if it
# appears in a URL.
_CODE_SUFFIXES = frozenset({
    "so", "py", "sh", "pl", "rs", "md", "cc", "zip", "mov", "now", "map",
    "open", "new", "run", "call", "select", "search", "data", "name", "id",
    "int", "page", "post", "do", "is", "as", "pm", "ps", "next", "one",
    "case", "java",
})


def _is_domain(text: str) -> bool:
    """A dotted name whose last label is a real top-level domain. Without
    this check `os.fork` and `fmt.pp` were reported as domains. With no
    suffix list (an image built before it was added) nothing is filtered."""
    if not _TLDS:
        return True
    labels = text.lower().rstrip(".").split(".")
    tld = labels[-1]
    return tld in _TLDS and tld not in _CODE_SUFFIXES and not labels[-2].isdigit()


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
        "domains": [d for d in decode(_DOMAIN.findall(blob), limit=400)
                    if _is_domain(d)][:25],
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
    if (result.get("archive") or {}).get("members"):
        return "interesting"       # unopened is not the same as unremarkable
    return "unremarkable"


def _mismatched(path: Path, sniffed: str | None, expected: str | None) -> bool:
    if sniffed is None:
        return False
    if expected:
        return expected != sniffed
    return path.suffix.lower() in _TEXTUAL_EXTS and sniffed in _BINARY_TYPES


MAX_MEMBERS = 200
_ARCHIVE_TYPES = {"zip archive", "gzip", "xz", "bzip2"}


def _archive_members(path: Path, sniffed: str | None) -> dict | None:
    """Names and sizes inside an archive, read from its index. Nothing is
    extracted to disk and no member's content is read: `hax3156.tgz` came
    back "unremarkable" because the analyser only hashed the outside."""
    if sniffed not in _ARCHIVE_TYPES:
        return None
    members, error, more = [], None, False
    try:
        if sniffed == "zip archive":
            import zipfile
            with zipfile.ZipFile(path) as z:
                infos = z.infolist()
                more = len(infos) > MAX_MEMBERS
                members = [{"name": i.filename[:300], "size": i.file_size}
                           for i in infos[:MAX_MEMBERS]]
        else:
            import tarfile
            with tarfile.open(path, "r:*") as tar:
                for info in tar:
                    if len(members) >= MAX_MEMBERS:
                        more = True
                        break
                    if info.isfile():
                        members.append({"name": info.name[:300], "size": info.size})
    except Exception as e:      # a single compressed file, a damaged or hostile archive
        error = f"{type(e).__name__}: {e}"[:200]
    return {"members": members, "more": more, "error": error}


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
    archive = _archive_members(path, sniffed)
    if archive is not None:
        result["archive"] = archive
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

    # rglob silently yields nothing for a directory it cannot read, which
    # would look exactly like an empty one.
    if not os.access(root, os.R_OK | os.X_OK):
        print(f"input directory {root} is not readable by uid {os.getuid()}",
              file=sys.stderr)
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
