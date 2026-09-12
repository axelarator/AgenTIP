"""Suite-wide hermeticity guard.

Every test file already stubs the enrichment boundaries it exercises
(pivot.*, webamon.*, vm_proxy.*), but those stubs are per-file and easy to
miss when a new code path reaches the network from somewhere unexpected.
The failure mode is quiet: with a probe VM configured and API keys exported
(CTI_PROBE_*/WEBAMON_API_KEY live in ~/.bashrc, which non-interactive
shells source), an unstubbed call doesn't error - it really does SSH to the
lab VM or hit a vendor API, so the suite's result depends on the machine
it runs on and on whether the lab is up.

So: block the transports outright, and unset the keys. A test that wants a
source to answer stubs that source, exactly as before - this only decides
what happens when nothing stubbed it.
"""
from __future__ import annotations

import socket

import pytest

from cti_tools import vm_proxy

_REAL_CONNECT = socket.socket.connect

# Keys the enrichment layer reads straight from the environment. Left set,
# a forgotten stub turns into a real, metered API call (and, for Webamon,
# spends daily budget).
_API_KEY_ENVS = ("WEBAMON_API_KEY", "HONEYLABS_API_KEY", "THREATFOX_API_KEY",
                 "VT_API_KEY")


@pytest.fixture(autouse=True)
def no_network(monkeypatch, request):
    for var in _API_KEY_ENVS:
        monkeypatch.delenv(var, raising=False)

    # test_vm_proxy drives _ssh_json_rpc deliberately, stubbing
    # subprocess.run itself; leave its transport alone (it never opens a
    # real socket) and just keep the socket guard below.
    if request.node.module.__name__.rsplit(".", 1)[-1] != "test_vm_proxy":
        def _blocked(request_payload, timeout=None):
            raise vm_proxy.VMProxyError(
                "probe VM access blocked in tests - stub the vm_proxy.* "
                "function this path calls (see tests/conftest.py)")
        monkeypatch.setattr(vm_proxy, "_ssh_json_rpc", _blocked)

    def _blocked_connect(self, address):
        raise AssertionError(
            f"test attempted a real network connection to {address!r} - "
            "stub the source it calls (see tests/conftest.py)")

    monkeypatch.setattr(socket.socket, "connect", _blocked_connect)
    yield
    monkeypatch.setattr(socket.socket, "connect", _REAL_CONNECT)
