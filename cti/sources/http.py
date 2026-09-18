"""The one HTTP transport.

## What this replaces

Four independent transports, each with its own User-Agent string, its own
timeout constant and its own idea of what an error looks like:

  pivot._get_text/_get_json/_post_json   -> vm_proxy, raised PivotError
  webamon._get                           -> urllib, returned error dicts
                                            keyed by status (401/403/429)
  report_ingest.fetch_text               -> urllib, raised its own error
  opensearch_client.search               -> http.client, retry-once
  (+ a byte-equivalent copy of the last one inside
   scripts/probe_pending_fingerprints.py)

## The two backends, and why the choice is explicit

`via="probe"` sends the request from the lab probe VM over SSH.
`via="direct"` sends it from this host.

That choice is an OPSEC decision, not a performance one, so it is a
required argument with no default. Anything that *names a tracked
indicator* - RDAP, RIPEstat, ThreatFox, DNS, TLS, HTTP - goes via the
probe VM, because an RDAP lookup on a malicious domain is still traffic
that tells a third party this host is interested in that domain, and a
live grab reaches the adversary's own infrastructure.

The documented exceptions go direct: Webamon and HoneyLabs are queries
against a vendor's own index, not against the indicator, and routing
them through the VM would burn its egress IP's shared allowance for no
benefit.

One undocumented exception existed and is now labelled: report_ingest
fetched analyst-supplied report URLs from this host. That is usually a
vendor blog, so it is defensible - but it was the only outbound path
that silently ignored the chokepoint rule. It now passes
`via="direct"` explicitly, so the exception is visible at the call site.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Literal

from ..errors import VMProxyError

USER_AGENT = "cti-graph/1.0 (+local analysis tool, on-demand only)"

DEFAULT_TIMEOUT = 30
MAX_BYTES = 2_000_000

Via = Literal["probe", "direct"]


class HttpError(RuntimeError):
    """A request failed, or came back with a >=400 status.

    Carries `status` and `body` so a caller can distinguish the cases it
    cares about - Webamon needs 401 vs 403 vs 429 - without every source
    module inventing its own error-dict vocabulary.
    """

    def __init__(self, message: str, *, status: int | None = None, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


@dataclass
class Response:
    status: int | None
    body: str
    headers: dict[str, str] = field(default_factory=dict)
    final_url: str | None = None

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except ValueError as e:
            raise HttpError(f"unparseable response: {e}",
                            status=self.status, body=self.body[:400]) from e


def fetch(url: str, *, via: Via, method: str = "GET",
          headers: dict[str, str] | None = None, data: str | None = None,
          timeout: int = DEFAULT_TIMEOUT, max_bytes: int = MAX_BYTES,
          raise_for_status: bool = True) -> Response:
    """One request. See the module docstring for how to pick `via`."""
    merged = {"User-Agent": USER_AGENT, **(headers or {})}
    if data is not None:
        merged.setdefault("Content-Type", "application/json")

    if via == "probe":
        resp = _fetch_probe(url, method, merged, data, timeout)
    elif via == "direct":
        resp = _fetch_direct(url, method, merged, data, timeout, max_bytes)
    else:
        raise ValueError(f"via must be 'probe' or 'direct', not {via!r}")

    if raise_for_status and resp.status is not None and resp.status >= 400:
        # An error body here is often a small JSON document whose detail is
        # far more actionable than the bare status code - ThreatFox's
        # {"query_status": "unknown_auth_key"} is the canonical example.
        detail = ""
        if resp.body:
            try:
                detail = f": {json.loads(resp.body)}"
            except ValueError:
                detail = f": {resp.body[:200]}"
        raise HttpError(f"{url} returned HTTP {resp.status}{detail}",
                        status=resp.status, body=resp.body)
    return resp


def _fetch_probe(url, method, headers, data, timeout) -> Response:
    """`timeout` is deliberately unused here: the probe hop's deadline is
    the SSH timeout (vm_proxy.SSH_TIMEOUT / LONG_TIMEOUT), not a per-request
    HTTP one, because the request is executed on the far side of the hop.
    Passing it through would be a TypeError against the real signature."""
    from ..probe import vm_proxy
    try:
        result = vm_proxy.http_fetch(url, headers=headers, method=method,
                                     data=data)
    except VMProxyError as e:
        raise HttpError(f"failed to reach {url} via the probe VM: {e}") from e
    return Response(status=result.get("status"),
                    body=str(result.get("body") or ""),
                    headers={k.lower(): v for k, v in (result.get("headers") or {}).items()},
                    final_url=result.get("final_url"))


def _fetch_direct(url, method, headers, data, timeout, max_bytes) -> Response:
    req = urllib.request.Request(
        url, method=method, headers=headers,
        data=data.encode() if isinstance(data, str) else data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(max_bytes).decode("utf-8", errors="replace")
            return Response(status=r.status, body=body,
                            headers={k.lower(): v for k, v in r.headers.items()},
                            final_url=r.geturl())
    except urllib.error.HTTPError as e:
        try:
            body = e.read(max_bytes).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return Response(status=e.code, body=body,
                        headers={k.lower(): v for k, v in (e.headers or {}).items()},
                        final_url=url)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise HttpError(f"failed to reach {url}: {e}") from e


def get_text(url: str, *, via: Via, **kw) -> str:
    """Some free enrichment endpoints return newline-delimited text rather
    than JSON, which is why this exists separately from get_json."""
    return fetch(url, via=via, **kw).body


def get_json(url: str, *, via: Via, **kw) -> Any:
    return fetch(url, via=via, **kw).json()


def post_json(url: str, payload: dict[str, Any], *, via: Via, **kw) -> Any:
    return fetch(url, via=via, method="POST", data=json.dumps(payload), **kw).json()
