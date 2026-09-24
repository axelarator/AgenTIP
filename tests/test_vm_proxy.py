"""Tests for cti_tools.vm_proxy. No real SSH/network calls - subprocess.run
is monkeypatched everywhere so the suite runs offline."""
from __future__ import annotations

import json

import pytest

from cti.probe import vm_proxy


class _FakeCompletedProcess:
    def __init__(self, stdout: str, stderr: str = "", returncode: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def test_ssh_json_rpc_round_trips_request_and_response(monkeypatch):
    captured = {}

    def fake_run(cmd, input=None, capture_output=None, text=None, timeout=None):
        captured["cmd"] = cmd
        captured["input"] = json.loads(input)
        return _FakeCompletedProcess(stdout=json.dumps({"ok": True}))

    monkeypatch.setattr(vm_proxy.subprocess, "run", fake_run)
    result = vm_proxy._ssh_json_rpc({"action": "http_fetch", "url": "https://example.com"})
    assert result == {"ok": True}
    assert captured["input"]["action"] == "http_fetch"
    assert f"{vm_proxy.PROBE_USER}@{vm_proxy.PROBE_HOST}" in captured["cmd"]


def test_ssh_json_rpc_transport_failure_raises_vmproxyerror(monkeypatch):
    def fake_run(cmd, input=None, capture_output=None, text=None, timeout=None):
        return _FakeCompletedProcess(stdout="", stderr="Connection refused", returncode=255)
    monkeypatch.setattr(vm_proxy.subprocess, "run", fake_run)
    with pytest.raises(vm_proxy.VMProxyError):
        vm_proxy._ssh_json_rpc({"action": "http_fetch"})


def test_ssh_json_rpc_non_json_stdout_raises_vmproxyerror(monkeypatch):
    def fake_run(cmd, input=None, capture_output=None, text=None, timeout=None):
        return _FakeCompletedProcess(stdout="not json")
    monkeypatch.setattr(vm_proxy.subprocess, "run", fake_run)
    with pytest.raises(vm_proxy.VMProxyError):
        vm_proxy._ssh_json_rpc({"action": "http_fetch"})


def test_http_fetch_returns_body_on_success(monkeypatch):
    monkeypatch.setattr(vm_proxy, "_ssh_json_rpc",
                        lambda request: {"status": 200, "body": "hello", "error": None})
    result = vm_proxy.http_fetch("https://example.com")
    assert result["status"] == 200
    assert result["body"] == "hello"


def test_http_fetch_raises_on_error_field(monkeypatch):
    monkeypatch.setattr(vm_proxy, "_ssh_json_rpc",
                        lambda request: {"status": None, "body": None, "error": "failed to reach host"})
    with pytest.raises(vm_proxy.VMProxyError):
        vm_proxy.http_fetch("https://example.com")


def test_http_fetch_passes_method_and_data_through(monkeypatch):
    captured = {}

    def fake_rpc(request):
        captured.update(request)
        return {"status": 200, "body": "{}", "error": None}

    monkeypatch.setattr(vm_proxy, "_ssh_json_rpc", fake_rpc)
    vm_proxy.http_fetch("https://example.com", method="POST", data='{"query": "search_ioc"}')
    assert captured["method"] == "POST"
    assert captured["data"] == '{"query": "search_ioc"}'


def test_http_fetch_defaults_data_to_none(monkeypatch):
    captured = {}

    def fake_rpc(request):
        captured.update(request)
        return {"status": 200, "body": "hello", "error": None}

    monkeypatch.setattr(vm_proxy, "_ssh_json_rpc", fake_rpc)
    vm_proxy.http_fetch("https://example.com")
    assert captured["data"] is None


def test_resolve_dns_resolved(monkeypatch):
    monkeypatch.setattr(vm_proxy, "_ssh_json_rpc",
                        lambda request: {"status": "resolved", "addrs": ["1.2.3.4"]})
    assert vm_proxy.resolve_dns("example.com") == ["1.2.3.4"]


def test_resolve_dns_nxdomain(monkeypatch):
    monkeypatch.setattr(vm_proxy, "_ssh_json_rpc", lambda request: {"status": "nxdomain"})
    assert vm_proxy.resolve_dns("nope.invalid") == []


def test_resolve_dns_inconclusive_error(monkeypatch):
    monkeypatch.setattr(vm_proxy, "_ssh_json_rpc",
                        lambda request: {"status": "error", "error": "timeout"})
    assert vm_proxy.resolve_dns("nope.invalid") is None


def test_probe_jarm_sends_jarm_probe_action(monkeypatch):
    captured = {}

    def fake_rpc(request):
        captured.update(request)
        return {"jarm": "abc", "resolved_ip": "1.2.3.4", "error": None}
    monkeypatch.setattr(vm_proxy, "_ssh_json_rpc", fake_rpc)
    result = vm_proxy.probe_jarm("example.com", 443)
    assert captured == {"action": "jarm_probe", "target": "example.com", "port": 443}
    assert result["jarm"] == "abc"


def test_ssh_json_rpc_uses_default_timeout(monkeypatch):
    captured = {}

    def fake_run(cmd, input=None, capture_output=None, text=None, timeout=None):
        captured["timeout"] = timeout
        return _FakeCompletedProcess(stdout=json.dumps({"ok": True}))

    monkeypatch.setattr(vm_proxy.subprocess, "run", fake_run)
    vm_proxy._ssh_json_rpc({"action": "http_fetch"})
    assert captured["timeout"] == vm_proxy.SSH_TIMEOUT


def test_ssh_json_rpc_honors_per_call_timeout(monkeypatch):
    captured = {}

    def fake_run(cmd, input=None, capture_output=None, text=None, timeout=None):
        captured["timeout"] = timeout
        return _FakeCompletedProcess(stdout=json.dumps({"ok": True}))

    monkeypatch.setattr(vm_proxy.subprocess, "run", fake_run)
    vm_proxy._ssh_json_rpc({"action": "nmap"}, timeout=900)
    assert captured["timeout"] == 900


def test_nmap_and_dirsearch_pass_long_timeout(monkeypatch):
    seen = []

    def fake_rpc(request, timeout=None):
        seen.append((request["action"], timeout))
        return {"ports": [], "opendirs": [], "hits": [], "error": None}

    monkeypatch.setattr(vm_proxy, "_ssh_json_rpc", fake_rpc)
    vm_proxy.nmap("1.2.3.4")
    vm_proxy.dirsearch("http://1.2.3.4/")
    assert seen == [("nmap", vm_proxy.LONG_TIMEOUT),
                    ("dirsearch", vm_proxy.LONG_TIMEOUT)]


def test_http_probe_and_dns_lookup_and_passive_actions(monkeypatch):
    seen = []

    def fake_rpc(request, timeout=None):
        seen.append(request["action"])
        return {"error": None}

    monkeypatch.setattr(vm_proxy, "_ssh_json_rpc", fake_rpc)
    vm_proxy.http_probe("https://example.com/")
    vm_proxy.dns_lookup("example.com")
    vm_proxy.subfinder("example.com")
    vm_proxy.wayback_cdx("example.com")
    assert seen == ["http_probe", "dns_lookup", "subfinder", "wayback_cdx"]


def test_probe_host_reads_environment(monkeypatch):
    # The connection details come from the environment so the same code
    # runs against whatever probe VM the lab currently uses.
    import importlib
    monkeypatch.setenv("CTI_PROBE_HOST", "10.99.0.5")
    monkeypatch.setenv("CTI_PROBE_USER", "probe")
    monkeypatch.setenv("CTI_PROBE_HELPER_CMD", "python3 /srv/helper.py")
    reloaded = importlib.reload(vm_proxy)
    try:
        assert reloaded.PROBE_HOST == "10.99.0.5"
        assert reloaded.PROBE_USER == "probe"
        assert reloaded.PROBE_HELPER_CMD == ["python3", "/srv/helper.py"]
    finally:
        monkeypatch.undo()
        importlib.reload(vm_proxy)


# --------------------------------------------------------------------------- #
# The concurrency cap - the first full fan-out lost 49 of 57 domain lookups
# --------------------------------------------------------------------------- #

def test_concurrent_probe_calls_never_exceed_the_cap(monkeypatch):
    """Every call is an ssh command multiplexed over ONE connection, and sshd
    allows ~10 sessions per connection. Nothing capped it, and fanning 9
    clusters x 6 workers out put up to 54 through at once."""
    import json
    import subprocess
    import threading
    import time

    cap = 3
    monkeypatch.setattr(vm_proxy, "_slots", threading.BoundedSemaphore(cap))
    lock, live, peak = threading.Lock(), [0], [0]

    def fake_run(cmd, **kw):
        with lock:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
        time.sleep(0.03)
        with lock:
            live[0] -= 1
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"ok": True}), stderr="")

    monkeypatch.setattr(vm_proxy.subprocess, "run", fake_run)
    results, errors = [], []

    def call():
        try:
            results.append(vm_proxy._ssh_json_rpc({"action": "x"}))
        except Exception as e:                          # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=call) for _ in range(30)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert errors == [] and len(results) == 30, "every call must still complete"
    assert peak[0] <= cap, f"{peak[0]} concurrent calls with a cap of {cap}"
    assert peak[0] > 1, "the cap must not serialise everything"


def test_the_ssh_timeout_is_not_charged_for_time_spent_waiting_for_a_slot(monkeypatch):
    """The slot is taken before subprocess.run's clock starts. Otherwise a
    queue behind the cap would itself cause the timeouts it exists to
    prevent."""
    import json
    import subprocess
    import threading

    monkeypatch.setattr(vm_proxy, "_slots", threading.BoundedSemaphore(1))
    seen = []

    def fake_run(cmd, **kw):
        seen.append(kw.get("timeout"))
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({}), stderr="")

    monkeypatch.setattr(vm_proxy.subprocess, "run", fake_run)
    vm_proxy._ssh_json_rpc({}, timeout=42)
    vm_proxy._ssh_json_rpc({})
    assert seen == [42, vm_proxy.SSH_TIMEOUT]


def test_a_failed_call_releases_its_slot(monkeypatch):
    """A leaked slot would starve the pool a call at a time until the whole
    sweep hangs."""
    import subprocess
    import threading

    monkeypatch.setattr(vm_proxy, "_slots", threading.BoundedSemaphore(1))

    def boom(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 60)

    monkeypatch.setattr(vm_proxy.subprocess, "run", boom)
    for _ in range(5):        # more attempts than slots
        with pytest.raises(vm_proxy.VMProxyError):
            vm_proxy._ssh_json_rpc({})


def test_the_cap_defaults_to_what_the_old_design_implied():
    """The old sweep peaked at its 6-worker pool."""
    assert vm_proxy._MAX_CONCURRENT == 6


def test_an_ssh_timeout_is_a_vmproxyerror_not_a_raw_timeoutexpired(monkeypatch):
    """Every handler in core catches VMProxyError. TimeoutExpired is not one,
    so it escaped them all and turned a whole domain 'unknown'."""
    import subprocess

    def boom(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 60)
    monkeypatch.setattr(vm_proxy.subprocess, "run", boom)
    with pytest.raises(vm_proxy.VMProxyError) as exc:
        vm_proxy._ssh_json_rpc({"action": "subfinder"}, timeout=42)
    assert "subfinder" in str(exc.value) and "42s" in str(exc.value)


def test_subfinder_is_given_more_time_than_the_ssh_default(monkeypatch):
    """Its helper-side budget on the VM is 180s. Waiting only 60s meant the
    SSH side gave up while the enumeration kept running on the VM."""
    seen = {}
    monkeypatch.setattr(vm_proxy, "_ssh_json_rpc",
                        lambda req, timeout=None: seen.update(timeout=timeout) or {})
    vm_proxy.subfinder("example.com")
    assert seen["timeout"] == vm_proxy.SUBFINDER_TIMEOUT > vm_proxy.SSH_TIMEOUT


def test_subfinders_budget_covers_the_helpers_own_limit():
    """The helper is the authority on how long subfinder may run; the SSH
    side must outlast it or the two disagree about when a run is dead."""
    import re
    from pathlib import Path
    helper = (Path(__file__).resolve().parents[1] / "probe_vm" / "probe_helper.py").read_text()
    body = helper[helper.index("def action_subfinder"):helper.index("def action_wayback_cdx")]
    helper_limit = int(re.search(r"timeout=(\d+)", body).group(1))
    assert vm_proxy.SUBFINDER_TIMEOUT > helper_limit


def test_the_openssl_tls_grab_is_gone():
    """The certificate is read off the observe pass (tlsx), which returns a
    superset of what the separate openssl handshake did. Keeping the wrapper
    would invite the second connection back."""
    assert not hasattr(vm_proxy, "tls_grab")


def test_stats_split_slot_wait_from_run_time(monkeypatch):
    """Whether the sweep is waiting on the slot ceiling or on the VM is
    the question that decides between more threads and a higher ceiling.
    With one slot and two 0.3s calls, the second queues ~0.3s."""
    import threading
    import time

    def fake_run(cmd, input=None, capture_output=None, text=None, timeout=None):
        time.sleep(0.3)
        return _FakeCompletedProcess(stdout=json.dumps({"ok": True}))

    monkeypatch.setattr(vm_proxy.subprocess, "run", fake_run)
    monkeypatch.setattr(vm_proxy, "_slots", threading.BoundedSemaphore(1))
    vm_proxy.reset_stats()
    calls = [threading.Thread(target=vm_proxy._ssh_json_rpc, args=({"action": "observe"},))
             for _ in range(2)]
    for t in calls:
        t.start()
    for t in calls:
        t.join()

    row = vm_proxy.stats()["actions"]["observe"]
    assert row["calls"] == 2 and row["timeouts"] == 0
    assert 0.5 <= row["run_s"] <= 0.8
    assert 0.2 <= row["wait_s"] <= 0.5


def test_stats_count_a_timeout(monkeypatch):
    import subprocess

    def fake_run(cmd, input=None, capture_output=None, text=None, timeout=None):
        raise subprocess.TimeoutExpired(cmd, timeout)

    monkeypatch.setattr(vm_proxy.subprocess, "run", fake_run)
    vm_proxy.reset_stats()
    with pytest.raises(vm_proxy.VMProxyError):
        vm_proxy._ssh_json_rpc({"action": "subfinder"})
    assert vm_proxy.stats()["actions"]["subfinder"]["timeouts"] == 1
