"""Minimal OpenSearch client for the lab's Arkime/OpenSearch VM.

Generalized from the query helpers in scripts/probe_pending_fingerprints.py
(which keeps its own copy for now) so package code can share one
transport. Plain HTTP, no auth - that VM's OpenSearch has no login in
front of it and is only reachable lab-internally. Not thread-safe: one
client instance per single-threaded caller, matching how the probe
script uses its module-global connection.

Documents in the zeek-* indices carry a flat numeric epoch `ts` plus
flattened `src_ip`/`dst_ip`/`src_port`/`dst_port` and `log_file`
(renames confirmed live 2026-07-20).
"""
from __future__ import annotations

import http.client
import json
import os
from typing import Any
from urllib.parse import urlsplit

DEFAULT_URL = os.environ.get("CTI_OPENSEARCH_URL", "http://10.20.0.18:9200")
DEFAULT_INDEX = os.environ.get("CTI_OPENSEARCH_INDEX", "zeek-*")


class OpenSearchError(Exception):
    pass


class OpenSearchClient:
    def __init__(self, url: str = DEFAULT_URL, index: str = DEFAULT_INDEX,
                 timeout: float = 15.0):
        parts = urlsplit(url)
        self._host = parts.hostname or url
        self._port = parts.port or 9200
        self._timeout = timeout
        self.index = index
        self._conn: http.client.HTTPConnection | None = None

    def _connection(self) -> http.client.HTTPConnection:
        if self._conn is None:
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
        request: dict[str, Any] = {"size": size, "query": query}
        if sort is not None:
            request["sort"] = sort
        if aggs is not None:
            request["aggs"] = aggs
        if source_fields is not None:
            request["_source"] = source_fields
        body = json.dumps(request).encode()
        headers = {"Content-Type": "application/json"}

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

    def current_max_ts(self) -> float:
        """Newest indexed `ts` (epoch seconds), 0.0 if the index is empty."""
        payload = self.search({"match_all": {}}, size=1,
                              sort=[{"ts": "desc"}], source_fields=["ts"])
        hits = payload.get("hits", {}).get("hits", [])
        return float(hits[0]["_source"]["ts"]) if hits else 0.0
