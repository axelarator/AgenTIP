"""Minimal OpenSearch client for the lab's Zeek logs.

Two backends hold Zeek data, and callers should not have to care which:

- `wazuh` (default since 2026-10-14): the lab's Zeek sensor ships every log
  to Wazuh, and they land in `wazuh-archives-*` on siem01 with the Zeek
  record under `data.` (scope separator "_", so `data.id_resp_h`). The
  indexer only listens on siem01's localhost, so this client opens an SSH
  tunnel through a forward-only login (CTI_WAZUH_TUNNEL) and authenticates
  as a read-only user. The archives also hold every non-Zeek event, so
  every query is pinned to the Zeek log paths.
- `arkime`: the legacy `zeek-*` indices on the Arkime VM, fed by fluent-bit
  until 2026-10-12. Plain HTTP, no auth, flattened `src_ip`/`dst_ip`/
  `log_file` (renames confirmed live 2026-07-20). History only now.

Callers write queries with LOGICAL field names through `field()` and get
documents back in the legacy flat shape from `sources()` (`ts` epoch
seconds, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `log_file`, plus the
Zeek fields themselves). Not thread-safe: one client per single-threaded
caller.
"""
from __future__ import annotations

import atexit
import base64
import http.client
import json
import os
import socket
import ssl
import subprocess
import time
from typing import Any
from urllib.parse import urlsplit

BACKEND = os.environ.get("CTI_ZEEK_BACKEND", "wazuh")

_BACKENDS: dict[str, dict[str, Any]] = {
    "wazuh": {
        "url": os.environ.get("CTI_WAZUH_URL", "https://127.0.0.1:19200"),
        "index": os.environ.get("CTI_WAZUH_INDEX", "wazuh-archives-*"),
        # Time is Wazuh's own `timestamp` (ingest time, seconds behind
        # Zeek's): data.ts is a date only in indices created after the typed
        # template, and sorting across a keyword index and a date index
        # fails outright. Documents still carry Zeek's ts (see flatten_wazuh).
        "fields": {"ts": "timestamp", "src_ip": "data.id_orig_h",
                   "dst_ip": "data.id_resp_h", "src_port": "data.id_orig_p",
                   "dst_port": "data.id_resp_p", "log_file": "location"},
        # Only the sensor's Zeek logs; the archives hold everything else too.
        "base_filter": {"prefix": {"location": "/opt/zeek/logs/"}},
        # `timestamp` is a date: min/max aggregations come back in epoch
        # MILLISECONDS, and a range is sent as integer milliseconds (a float
        # bound serialises as 1.79E9, which the date parser rejects).
        "agg_ts_scale": 1000.0,
        "ts_format": "epoch_millis",
    },
    "arkime": {
        # The real address is lab topology and comes from the environment;
        # this file is public, so the fallback names nothing.
        "url": os.environ.get("CTI_OPENSEARCH_URL", "http://127.0.0.1:9200"),
        "index": os.environ.get("CTI_OPENSEARCH_INDEX", "zeek-*"),
        "fields": {"ts": "ts", "src_ip": "src_ip.keyword",
                   "dst_ip": "dst_ip.keyword", "src_port": "src_port",
                   "dst_port": "dst_port", "log_file": "log_file.keyword"},
        "base_filter": None,
        "agg_ts_scale": 1.0,
        "ts_format": None,
    },
}

# Kept for callers that imported them.
DEFAULT_URL = _BACKENDS[BACKEND]["url"] if BACKEND in _BACKENDS else ""
DEFAULT_INDEX = _BACKENDS[BACKEND]["index"] if BACKEND in _BACKENDS else ""

_tunnel: subprocess.Popen | None = None


def _listening(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _ensure_tunnel(host: str, port: int) -> None:
    """Open the SSH forward to siem01's indexer unless something already
    listens on the local end (a long-lived tunnel, or an earlier call).

    The login it uses can forward to 127.0.0.1:9200 and nothing else, so
    a failure here is a transport error like any other.
    """
    global _tunnel
    target = os.environ.get("CTI_WAZUH_TUNNEL", "")
    if not target or _listening(host, port):
        return
    cmd = ["ssh", "-N", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
           "-o", "ServerAliveInterval=30",
           "-L", f"{host}:{port}:127.0.0.1:9200"]
    if os.environ.get("CTI_WAZUH_SSH_KEY"):
        cmd += ["-i", os.environ["CTI_WAZUH_SSH_KEY"], "-o", "IdentitiesOnly=yes"]
    if os.environ.get("CTI_WAZUH_KNOWN_HOSTS"):
        cmd += ["-o", f"UserKnownHostsFile={os.environ['CTI_WAZUH_KNOWN_HOSTS']}"]
    _tunnel = subprocess.Popen(cmd + [target], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    atexit.register(_close_tunnel)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if _tunnel.poll() is not None:
            err = (_tunnel.stderr.read() or b"").decode(errors="replace").strip()
            _tunnel = None
            raise OpenSearchError(f"SSH tunnel to {target} failed: {err}")
        if _listening(host, port):
            return
        time.sleep(0.2)
    raise OpenSearchError(f"SSH tunnel to {target} did not come up within 10s")


def _close_tunnel() -> None:
    global _tunnel
    if _tunnel is not None and _tunnel.poll() is None:
        _tunnel.terminate()
        try:
            _tunnel.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _tunnel.kill()
    _tunnel = None


def flatten_wazuh(source: dict[str, Any]) -> dict[str, Any]:
    """One wazuh-archives document in the legacy flat zeek-* shape."""
    data = dict(source.get("data") or {})
    doc = dict(data)
    doc["src_ip"] = data.get("id_orig_h")
    doc["dst_ip"] = data.get("id_resp_h")
    for key, src in (("src_port", "id_orig_p"), ("dst_port", "id_resp_p")):
        try:
            doc[key] = int(data[src]) if data.get(src) not in (None, "") else None
        except (TypeError, ValueError):
            doc[key] = None
    try:
        doc["ts"] = float(data["ts"]) if data.get("ts") not in (None, "") else 0.0
    except (TypeError, ValueError):
        doc["ts"] = 0.0
    doc["log_file"] = source.get("location", "")
    # Zeek writes booleans as JSON booleans; Wazuh's decoder hands some of
    # them over as strings.
    if isinstance(doc.get("established"), str):
        doc["established"] = doc["established"].lower() == "true"
    return doc


class OpenSearchError(Exception):
    pass


class OpenSearchClient:
    def __init__(self, url: str | None = None, index: str | None = None,
                 timeout: float = 15.0, backend: str | None = None):
        self.backend = backend or BACKEND
        if self.backend not in _BACKENDS:
            raise ValueError(f"unknown Zeek backend {self.backend!r}")
        spec = _BACKENDS[self.backend]
        url = url or spec["url"]
        parts = urlsplit(url)
        self._https = parts.scheme == "https"
        self._host = parts.hostname or url
        self._port = parts.port or 9200
        self._timeout = timeout
        self.url = url
        self.index = index or spec["index"]
        self._fields: dict[str, str] = spec["fields"]
        self._base_filter = spec["base_filter"]
        self._agg_ts_scale: float = spec["agg_ts_scale"]
        self._ts_format: str | None = spec["ts_format"]
        self._headers = {"Content-Type": "application/json"}
        if self.backend == "wazuh":
            user = os.environ.get("CTI_WAZUH_USER", "cti_reader")
            password = os.environ.get("CTI_WAZUH_PASSWORD", "")
            token = base64.b64encode(f"{user}:{password}".encode()).decode()
            self._headers["Authorization"] = f"Basic {token}"
        self._conn: http.client.HTTPConnection | None = None

    def field(self, logical: str) -> str:
        """The physical field for a logical name (ts, src_ip, dst_ip,
        src_port, dst_port, log_file), exact-match where that matters."""
        return self._fields[logical]

    def ts_range(self, gte: float | None = None, lt: float | None = None) -> dict[str, Any]:
        """A range filter on event time, bounds in epoch seconds."""
        def convert(value: float) -> float | int:
            return int(value * 1000) if self._ts_format == "epoch_millis" else value

        bounds: dict[str, Any] = {}
        if gte is not None:
            bounds["gte"] = convert(gte)
        if lt is not None:
            bounds["lt"] = convert(lt)
        if self._ts_format:
            bounds["format"] = self._ts_format
        return {"range": {self.field("ts"): bounds}}

    def agg_epoch(self, value: Any) -> float | None:
        """A min/max aggregation over `ts`, as epoch seconds."""
        if value is None:
            return None
        return float(value) / self._agg_ts_scale

    def _connection(self) -> http.client.HTTPConnection:
        if self._conn is None:
            if self.backend == "wazuh":
                _ensure_tunnel(self._host, self._port)
            if self._https:
                # The indexer's certificate is self-signed for siem01, and
                # this connection only ever reaches it through the local end
                # of an SSH tunnel, which is what authenticates the host.
                context = ssl.create_default_context()
                if self._host in ("127.0.0.1", "localhost"):
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                self._conn = http.client.HTTPSConnection(
                    self._host, self._port, timeout=self._timeout, context=context)
            else:
                self._conn = http.client.HTTPConnection(
                    self._host, self._port, timeout=self._timeout)
        return self._conn

    def _reset(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def search(self, query: dict[str, Any], *, size: int = 50,
               aggs: dict[str, Any] | None = None,
               source_fields: list[str] | None = None,
               sort: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """POST to /{index}/_search and return the full response body
        (so aggregations work). Retries once over a fresh connection if
        the reused keep-alive connection went stale; raises
        OpenSearchError on transport/HTTP failure."""
        if self._base_filter is not None:
            query = {"bool": {"filter": [self._base_filter, query]}}
        request: dict[str, Any] = {"size": size, "query": query}
        if sort is not None:
            request["sort"] = sort
        if aggs is not None:
            request["aggs"] = aggs
        if source_fields is not None:
            request["_source"] = source_fields
        body = json.dumps(request).encode()
        headers = self._headers

        last_error: Exception | None = None
        for _ in range(2):
            conn = self._connection()
            try:
                conn.request("POST", f"/{self.index}/_search",
                             body=body, headers=headers)
                resp = conn.getresponse()
                payload = json.loads(resp.read())
                if resp.status >= 400:
                    raise OpenSearchError(
                        f"OpenSearch query failed: HTTP {resp.status}: {payload}")
                return payload
            except (http.client.HTTPException, TimeoutError, OSError, ValueError) as e:
                last_error = e
                self._reset()
        raise OpenSearchError(f"OpenSearch query failed: {last_error}") from last_error

    def sources(self, query: dict[str, Any], *, size: int = 50) -> list[dict[str, Any]]:
        """The newest-first list of `_source` documents for a query.

        The shape the netwatch passive join needs. The retired fingerprint
        queue script once had its own copy of this whole client; search()
        returns the full body instead because the daily Zeek cross-
        reference needs aggregations. One client, two accessors.
        """
        body = self.search(query, size=size, sort=[{self.field("ts"): "desc"}])
        return [self._flat(hit["_source"]) for hit in body["hits"]["hits"]]

    def _flat(self, source: dict[str, Any]) -> dict[str, Any]:
        return flatten_wazuh(source) if self.backend == "wazuh" else source


    def current_max_ts(self) -> float:
        """Newest indexed `ts` (epoch seconds), 0.0 if the index is empty."""
        payload = self.search({"match_all": {}}, size=1,
                              sort=[{self.field("ts"): "desc"}])
        hits = payload.get("hits", {}).get("hits", [])
        return float(self._flat(hits[0]["_source"]).get("ts") or 0.0) if hits else 0.0
