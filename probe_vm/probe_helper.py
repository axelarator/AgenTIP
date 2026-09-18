"""Runs on the lab probe VM (a Linux box with VPN egress, sitting as an
ordinary port on the same mirrored bridge as the Zeek sensor - so every
request it makes is captured to Zeek/OpenSearch/Arkime for read-back).
The active half of the enrichment handoff: the cti host
(cti_tools/vm_proxy.py and probe_pending_fingerprints.py) sends this one
JSON request on stdin and reads one JSON response on stdout, per the SSH
forced-command protocol.

Standalone - not part of the cti_tools package. Standard library plus
`certifi`, shelling out to `dig`, `openssl`, `nmap`, `subfinder`, and
`dirsearch` where those tools do the job better than hand-rolled code.
Every action names a tracked indicator and is meant to originate from
this VM rather than the analyst's own host.

Actions (selected by the request's "action" field; "jarm_probe" is the
default for back-compat with the original single-purpose helper):

  jarm_probe   {target, port}                    -> {jarm, resolved_ip, error}
  http_fetch   {url, method, headers, data,      -> {status, body, error}
                insecure}
  resolve_dns  {host}                            -> {status, addrs}|{status:nxdomain}|{status:error,error}
  resolve_ptr  {ip}                              -> {status, hostname}|{status:no_ptr}|{status:error,error}
  dns_lookup   {host, types:[A,AAAA,MX,NS,TXT]}  -> {records:{TYPE:[...]}, error}
  tls_grab     {host, port}                      -> {cert:{sha256,issuer,subject,sans,not_before,not_after,protocol}, resolved_ip, error}
  http_probe   {url, insecure}                   -> {status, final_url, title, server, content_type, body_sha256, autoindex, error}
  subfinder    {domain}                          -> {subdomains:[...], error}
  wayback_cdx  {domain}                          -> {urls:[...], subdomains:[...], error}
  nmap         {target, top, sv}                 -> {ports:[{port,proto,service,product,version}], resolved_ip, error}
  dirsearch    {url, extensions, rate,           -> {hits:[{path,status,size}], opendirs:[{url,files:[...]}], baseline_404, error}
                max_depth, max_files}

`--check-access` runs a trivial self-test (imports, tool availability)
and prints a JSON status instead of reading stdin.
"""
from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

try:
    import certifi
    _CA_FILE = certifi.where()
except Exception:  # certifi optional; fall back to the system store
    _CA_FILE = None

# --- adjust for your environment --------------------------------------------
JARM_CMD = ["python3", "/opt/jarm/jarm.py"]      # salesforce/jarm CLI
SUBFINDER_CMD = ["subfinder"]
NMAP_CMD = ["nmap"]
DIRSEARCH_CMD = ["dirsearch"]
OPENSSL_CMD = ["openssl"]
DIG_CMD = ["dig"]

HTTP_TIMEOUT = 20
TCP_PRECHECK_TIMEOUT = 3
JARM_SUBPROCESS_TIMEOUT = 20
TLS_TIMEOUT = 15
HTTP_PROBE_MAX_BYTES = 512_000        # bounded body read for http_probe
WAYBACK_TIMEOUT = 30
NMAP_TIMEOUT = 600
DIRSEARCH_TIMEOUT = 600
OPENDIR_DIR_TIMEOUT = 20              # per-directory autoindex fetch
# -----------------------------------------------------------------------------

_HTTPS_CONTEXT = (ssl.create_default_context(cafile=_CA_FILE)
                  if _CA_FILE else ssl.create_default_context())
_INSECURE_CONTEXT = ssl.create_default_context()
_INSECURE_CONTEXT.check_hostname = False
_INSECURE_CONTEXT.verify_mode = ssl.CERT_NONE


# --------------------------------------------------------------------------- #
# helpers shared across actions
# --------------------------------------------------------------------------- #
def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_target_ip(target: str) -> str:
    return target if is_ip_literal(target) else socket.gethostbyname(target)


# --------------------------------------------------------------------------- #
# jarm_probe (ported from win_probe_helper.py)
# --------------------------------------------------------------------------- #
def tcp_precheck(resolved_ip: str, port: int) -> bool:
    try:
        with socket.create_connection((resolved_ip, port), timeout=TCP_PRECHECK_TIMEOUT):
            return True
    except OSError:
        return False


def run_jarm(target: str, port: int) -> str | None:
    proc = subprocess.run([*JARM_CMD, "-p", str(port), target],
                          capture_output=True, text=True, timeout=JARM_SUBPROCESS_TIMEOUT)
    line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    if ":" not in line:
        return None
    return line.split(":", 1)[1].strip() or None


def run_tls_handshake(target: str, resolved_ip: str, port: int) -> None:
    """One ordinary handshake, result discarded - it exists purely to give
    Zeek something real to fingerprint (ja4s/ja4ts/ja4l), read back
    separately. Connects to resolved_ip (not target) so it can't hit a
    different IP than the one reported back to the caller."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    server_hostname = None if is_ip_literal(target) else target
    with socket.create_connection((resolved_ip, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=server_hostname):
            pass


def action_jarm_probe(request: dict) -> dict:
    target = request["target"]
    port = int(request.get("port") or 443)
    response: dict[str, object] = {"jarm": None, "resolved_ip": None, "error": None}
    try:
        resolved_ip = resolve_target_ip(target)
        response["resolved_ip"] = resolved_ip
    except Exception as e:
        return {"jarm": None, "resolved_ip": None,
                "error": f"DNS resolution failed for {target!r}: {e}"}
    if not tcp_precheck(resolved_ip, port):
        response["error"] = (f"port {port} on {resolved_ip} refused/unreachable during a "
                             f"{TCP_PRECHECK_TIMEOUT}s TCP pre-check")
        return response
    try:
        response["jarm"] = run_jarm(target, port)
    except Exception as e:
        response["error"] = f"jarm failed: {e}"
    try:
        run_tls_handshake(target, resolved_ip, port)
    except Exception as e:
        existing = response.get("error")
        response["error"] = (f"{existing}; handshake failed: {e}" if existing
                             else f"handshake failed: {e}")
    return response


# --------------------------------------------------------------------------- #
# http_fetch (ported)
# --------------------------------------------------------------------------- #
def action_http_fetch(request: dict) -> dict:
    url = request["url"]
    method = request.get("method", "GET")
    headers = request.get("headers") or {}
    data = request.get("data")
    insecure = bool(request.get("insecure", False))
    body_bytes = data.encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body_bytes, method=method, headers=headers)
    context = _INSECURE_CONTEXT if insecure else _HTTPS_CONTEXT
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=context) as resp:
            return {"status": resp.status,
                    "body": resp.read().decode("utf-8", errors="replace"), "error": None}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read().decode("utf-8", errors="replace"),
                "error": None}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"status": None, "body": None, "error": f"failed to reach {url}: {e}"}


# --------------------------------------------------------------------------- #
# resolve_dns / resolve_ptr (ported) + dns_lookup (new)
# --------------------------------------------------------------------------- #
def action_resolve_dns(request: dict) -> dict:
    try:
        infos = socket.getaddrinfo(request["host"], None)
    except socket.gaierror:
        return {"status": "nxdomain"}
    except OSError as e:
        return {"status": "error", "error": str(e)}
    return {"status": "resolved", "addrs": sorted({info[4][0] for info in infos})}


def action_resolve_ptr(request: dict) -> dict:
    try:
        hostname, _a, _b = socket.gethostbyaddr(request["ip"])
    except socket.herror:
        return {"status": "no_ptr"}
    except OSError as e:
        return {"status": "error", "error": str(e)}
    return {"status": "resolved", "hostname": hostname}


def action_dns_lookup(request: dict) -> dict:
    host = request["host"]
    types = request.get("types") or ["A", "AAAA", "MX", "NS", "TXT"]
    records: dict[str, list[str]] = {}
    try:
        for rr in types:
            proc = subprocess.run([*DIG_CMD, "+short", host, rr],
                                  capture_output=True, text=True, timeout=15)
            vals = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
            if vals:
                records[rr] = vals
    except FileNotFoundError:
        return {"records": {}, "error": "dig not installed on probe VM"}
    except Exception as e:
        return {"records": records, "error": str(e)}
    return {"records": records, "error": None}


# --------------------------------------------------------------------------- #
# tls_grab (new) - live current certificate
# --------------------------------------------------------------------------- #
def _parse_openssl_cert(der: bytes) -> dict:
    """Fields from a DER cert via `openssl x509`. Python's ssl can't parse
    an unverified peer cert (getpeercert() returns {} under CERT_NONE), and
    we deliberately want the cert even when it's self-signed/expired
    (adversary infra), so shell to openssl for the human-readable fields."""
    out: dict[str, object] = {"issuer": None, "subject": None, "sans": [],
                              "not_before": None, "not_after": None}
    try:
        proc = subprocess.run(
            [*OPENSSL_CMD, "x509", "-inform", "DER", "-noout",
             "-issuer", "-subject", "-startdate", "-enddate", "-ext", "subjectAltName"],
            input=der, capture_output=True, timeout=15)
        text = proc.stdout.decode("utf-8", errors="replace")
    except Exception:
        return out
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("issuer="):
            out["issuer"] = line[len("issuer="):].strip()
        elif line.startswith("subject="):
            out["subject"] = line[len("subject="):].strip()
        elif line.startswith("notBefore="):
            out["not_before"] = line[len("notBefore="):].strip()
        elif line.startswith("notAfter="):
            out["not_after"] = line[len("notAfter="):].strip()
        elif "DNS:" in line:
            out["sans"] = sorted({m for m in re.findall(r"DNS:([^,\s]+)", line)})
    return out


def action_tls_grab(request: dict) -> dict:
    host = request["host"]
    port = int(request.get("port") or 443)
    try:
        resolved_ip = resolve_target_ip(host)
    except Exception as e:
        return {"cert": None, "resolved_ip": None, "error": f"DNS resolution failed: {e}"}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    server_hostname = None if is_ip_literal(host) else host
    try:
        with socket.create_connection((resolved_ip, port), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname) as tls:
                der = tls.getpeercert(binary_form=True)
                protocol = tls.version()
    except Exception as e:
        return {"cert": None, "resolved_ip": resolved_ip, "error": f"TLS grab failed: {e}"}
    if not der:
        return {"cert": None, "resolved_ip": resolved_ip, "error": "no peer certificate"}
    cert = _parse_openssl_cert(der)
    cert["sha256"] = hashlib.sha256(der).hexdigest()
    cert["protocol"] = protocol
    return {"cert": cert, "resolved_ip": resolved_ip, "error": None}


# --------------------------------------------------------------------------- #
# http_probe (new) - one browser-like GET + autoindex detection
# --------------------------------------------------------------------------- #
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_AUTOINDEX_MARKERS = ("Index of /", "<title>Index of", "Directory Listing For",
                      "Directory listing for")


def _fetch(url: str, insecure: bool = False, max_bytes: int = HTTP_PROBE_MAX_BYTES,
           timeout: int = HTTP_TIMEOUT) -> dict:
    context = _INSECURE_CONTEXT if insecure else _HTTPS_CONTEXT
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (cti-agent probe)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            body = resp.read(max_bytes)
            return {"status": resp.status, "final_url": resp.geturl(),
                    "headers": {k.lower(): v for k, v in resp.headers.items()},
                    "body": body.decode("utf-8", errors="replace"), "error": None}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(max_bytes).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {"status": e.code, "final_url": url,
                "headers": {k.lower(): v for k, v in (e.headers or {}).items()},
                "body": body, "error": None}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"status": None, "final_url": url, "headers": {}, "body": "",
                "error": f"failed to reach {url}: {e}"}


def parse_autoindex(body: str, base_url: str) -> list[dict] | None:
    """Parse an open-directory (autoindex) HTML page into file entries.
    Handles Apache/nginx/lighttpd and Python http.server listings. Returns
    None if the page doesn't look like a directory listing."""
    if not any(m in body for m in _AUTOINDEX_MARKERS):
        return None
    files: list[dict] = []
    # One anchor per entry, then whatever trails it up to the row/line end -
    # covers Apache/nginx `<pre>` listings (date + size as plain text after
    # the link), table-based listings (`</td><td>` cells), and Python
    # http.server's bare `<li><a>` (no trailing metadata at all).
    date_re = re.compile(r"(\d{4}-\d{2}-\d{2}[ T]?\d{0,2}:?\d{0,2}|\d{1,2}-\w{3}-\d{4}\s+\d{2}:\d{2})")
    size_re = re.compile(r"(\d[\d.,]*\s?[KMGT]?B?|\d+|-)\s*(?:</td>|$)")
    for m in re.finditer(r'<a\s+href="([^"?#]+)"[^>]*>([^<]+)</a>(.*?)(?:</tr>|\n|<br|$)',
                         body, re.IGNORECASE | re.DOTALL):
        href, name, tail = m.group(1), html.unescape(m.group(2).strip()), m.group(3)
        if href in ("../", "..", "/") or name in ("Parent Directory", ".."):
            continue
        if href.startswith(("?", "#", "http://", "https://", "mailto:")):
            continue
        tail = re.sub(r"<[^>]+>", " ", tail)
        dm, sm = date_re.search(tail), size_re.search(tail.strip())
        files.append({
            "name": name.rstrip("/"),
            "href": urllib.parse.urljoin(base_url, href),
            "is_dir": href.endswith("/"),
            "size": (sm.group(1).strip() if sm and sm.group(1).strip() not in ("", "-") else None),
            "mtime": (dm.group(1).strip() if dm else None),
        })
    return files


def action_http_probe(request: dict) -> dict:
    url = request["url"]
    insecure = bool(request.get("insecure", False))
    r = _fetch(url, insecure=insecure)
    if r["error"]:
        return {"status": None, "final_url": url, "title": None, "server": None,
                "content_type": None, "body_sha256": None, "autoindex": None,
                "error": r["error"]}
    body = r["body"]
    title_m = _TITLE_RE.search(body)
    autoindex = parse_autoindex(body, r["final_url"])
    return {
        "status": r["status"], "final_url": r["final_url"],
        "title": html.unescape(title_m.group(1).strip()) if title_m else None,
        "server": r["headers"].get("server"),
        "content_type": r["headers"].get("content-type"),
        "body_sha256": hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest(),
        "autoindex": {"url": r["final_url"], "files": autoindex} if autoindex is not None else None,
        "error": None,
    }


# --------------------------------------------------------------------------- #
# subfinder / wayback_cdx (new) - passive subdomain discovery
# --------------------------------------------------------------------------- #
def action_subfinder(request: dict) -> dict:
    domain = request["domain"]
    try:
        proc = subprocess.run([*SUBFINDER_CMD, "-silent", "-d", domain],
                              capture_output=True, text=True, timeout=180)
    except FileNotFoundError:
        return {"subdomains": [], "error": "subfinder not installed on probe VM"}
    except Exception as e:
        return {"subdomains": [], "error": str(e)}
    subs = sorted({ln.strip().lower() for ln in proc.stdout.splitlines() if ln.strip()})
    return {"subdomains": subs, "error": None}


def action_wayback_cdx(request: dict) -> dict:
    domain = request["domain"]
    cdx = ("https://web.archive.org/cdx/search/cdx?url=*." +
           urllib.parse.quote(domain) +
           "&output=json&fl=original&collapse=urlkey&limit=5000")
    r = _fetch(cdx, max_bytes=4_000_000, timeout=WAYBACK_TIMEOUT)
    if r["error"]:
        return {"urls": [], "subdomains": [], "error": r["error"]}
    try:
        rows = json.loads(r["body"])
    except Exception as e:
        return {"urls": [], "subdomains": [], "error": f"bad CDX response: {e}"}
    urls = sorted({row[0] for row in rows[1:] if row}) if isinstance(rows, list) else []
    subs = set()
    for u in urls:
        host = urllib.parse.urlparse(u).hostname
        if host and (host == domain or host.endswith("." + domain)):
            subs.add(host.lower())
    return {"urls": urls[:5000], "subdomains": sorted(subs), "error": None}


# --------------------------------------------------------------------------- #
# nmap (new, on-demand)
# --------------------------------------------------------------------------- #
def action_nmap(request: dict) -> dict:
    target = request["target"]
    top = int(request.get("top") or 100)
    sv = bool(request.get("sv", True))
    try:
        resolved_ip = resolve_target_ip(target)
    except Exception as e:
        return {"ports": [], "resolved_ip": None, "error": f"DNS resolution failed: {e}"}
    cmd = [*NMAP_CMD, "--top-ports", str(top), "-Pn", "-oX", "-"]
    if sv:
        cmd.append("-sV")
    cmd.append(target)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=NMAP_TIMEOUT)
    except FileNotFoundError:
        return {"ports": [], "resolved_ip": resolved_ip, "error": "nmap not installed on probe VM"}
    except Exception as e:
        return {"ports": [], "resolved_ip": resolved_ip, "error": str(e)}
    ports = []
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(proc.stdout)
        for port in root.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            ports.append({
                "port": int(port.get("portid")), "proto": port.get("protocol"),
                "service": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
            })
    except Exception as e:
        return {"ports": [], "resolved_ip": resolved_ip, "error": f"nmap XML parse failed: {e}"}
    return {"ports": ports, "resolved_ip": resolved_ip, "error": None}


# --------------------------------------------------------------------------- #
# dirsearch (new, on-demand) - path map + recursive open-directory listing
# --------------------------------------------------------------------------- #
def _random_path() -> str:
    import secrets
    return "/" + secrets.token_hex(12)


def _baseline_404(base: str) -> dict:
    """Fetch a definitely-nonexistent path so soft-404s (a 200 catch-all
    page) can be told apart from real hits by (status, size class)."""
    r = _fetch(urllib.parse.urljoin(base, _random_path()))
    return {"status": r["status"], "size": len(r["body"]) if r["body"] else 0}


def _is_soft_404(status: int | None, size: int, baseline: dict) -> bool:
    if status == baseline.get("status") and status not in (404, None):
        # same status as a known-missing path; treat near-equal sizes as the
        # catch-all page rather than a real, differently-sized document.
        b = baseline.get("size") or 0
        return abs(size - b) <= max(64, int(b * 0.05))
    return False


def _crawl_opendir(url: str, baseline: dict, max_depth: int, max_files: int,
                   seen: set[str], files_acc: list[dict], depth: int = 0) -> dict | None:
    """Breadth-first autoindex crawl from `url`, bounded by max_depth and a
    global max_files. Returns the listing dict for `url`, recursing into
    listed subdirectories."""
    if url in seen or len(files_acc) >= max_files or depth > max_depth:
        return None
    seen.add(url)
    r = _fetch(url, timeout=OPENDIR_DIR_TIMEOUT)
    if r["error"]:
        return None
    files = parse_autoindex(r["body"], r["final_url"])
    if files is None:
        return None
    listing = {"url": r["final_url"], "files": []}
    for f in files:
        if len(files_acc) >= max_files:
            break
        listing["files"].append(f)
        files_acc.append({"url": r["final_url"], **f})
        if f["is_dir"]:
            _crawl_opendir(f["href"], baseline, max_depth, max_files,
                           seen, files_acc, depth + 1)
    return listing


def action_dirsearch(request: dict) -> dict:
    url = request["url"]
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if not url.endswith("/"):
        url += "/"
    extensions = request.get("extensions") or ["php", "html", "js", "json", "txt", "bak", "zip"]
    rate = int(request.get("rate") or 20)
    max_depth = int(request.get("max_depth") or 3)
    max_files = int(request.get("max_files") or 2000)

    baseline = _baseline_404(url)
    hits: list[dict] = []
    # Path discovery via dirsearch, if available. Absence is non-fatal - the
    # open-directory crawl below is the higher-value half and needs no wordlist.
    if shutil.which(DIRSEARCH_CMD[0]):
        import tempfile
        import os
        with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
            report = tf.name
        try:
            subprocess.run(
                [*DIRSEARCH_CMD, "-u", url, "-e", ",".join(extensions),
                 "--max-rate", str(rate), "-q", "--format", "json", "-o", report],
                capture_output=True, text=True, timeout=DIRSEARCH_TIMEOUT)
            with open(report) as fh:
                data = json.load(fh)
            for item in (data.get("results") or []):
                status = item.get("status")
                size = item.get("content-length") or item.get("length") or 0
                if _is_soft_404(status, int(size or 0), baseline):
                    continue
                hits.append({"path": item.get("path") or item.get("url"),
                             "status": status, "size": size})
        except Exception:
            pass
        finally:
            try:
                os.unlink(report)
            except OSError:
                pass

    # Open-directory crawl: root plus every directory dirsearch surfaced.
    seen: set[str] = set()
    files_acc: list[dict] = []
    opendirs: list[dict] = []
    roots = [url] + [urllib.parse.urljoin(url, h["path"]) for h in hits
                     if str(h.get("path", "")).endswith("/")]
    for root in roots:
        listing = _crawl_opendir(root, baseline, max_depth, max_files, seen, files_acc)
        if listing:
            opendirs.append(listing)
        if len(files_acc) >= max_files:
            break
    return {"hits": hits, "opendirs": opendirs, "baseline_404": baseline, "error": None}


# --------------------------------------------------------------------------- #
# dispatch
# --------------------------------------------------------------------------- #
_ACTIONS = {
    "jarm_probe": action_jarm_probe,
    "http_fetch": action_http_fetch,
    "resolve_dns": action_resolve_dns,
    "resolve_ptr": action_resolve_ptr,
    "dns_lookup": action_dns_lookup,
    "tls_grab": action_tls_grab,
    "http_probe": action_http_probe,
    "subfinder": action_subfinder,
    "wayback_cdx": action_wayback_cdx,
    "nmap": action_nmap,
    "dirsearch": action_dirsearch,
}


def _tool_present(cmd: list[str]) -> bool:
    # An interpreter + script command (JARM_CMD) needs the script on disk
    # too - `which python3` alone would report jarm present when it isn't.
    return bool(shutil.which(cmd[0])) and all(
        os.path.exists(a) for a in cmd[1:] if a.startswith("/"))


def check_access() -> dict:
    tools = {name: _tool_present(cmd) for name, cmd in {
        "jarm": JARM_CMD, "subfinder": SUBFINDER_CMD, "nmap": NMAP_CMD,
        "dirsearch": DIRSEARCH_CMD, "openssl": OPENSSL_CMD, "dig": DIG_CMD}.items()}
    return {"ok": True, "certifi": _CA_FILE is not None, "tools": tools}


def main() -> int:
    if "--check-access" in sys.argv[1:]:
        json.dump(check_access(), sys.stdout)
        return 0
    try:
        request = json.loads(sys.stdin.read() or "{}")
        action = request.get("action", "jarm_probe")
    except Exception as e:
        json.dump({"error": f"bad request: {e}"}, sys.stdout)
        return 1
    handler = _ACTIONS.get(action)
    if handler is None:
        json.dump({"error": f"unknown action: {action!r}"}, sys.stdout)
        return 1
    try:
        result = handler(request)
    except Exception as e:
        result = {"error": f"{action} failed: {e}"}
    json.dump(result, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
