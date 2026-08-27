"""Tests for cti_tools.vm_proxy. No real SSH/network calls - subprocess.run
is monkeypatched everywhere so the suite runs offline."""
from __future__ import annotations

import json

import pytest

from cti_tools import vm_proxy


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
    assert f"{vm_proxy.WIN_PROBE_USER}@{vm_proxy.WIN_PROBE_HOST}" in captured["cmd"]


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


def test_probe_win_sends_jarm_probe_action(monkeypatch):
    captured = {}

    def fake_rpc(request):
        captured.update(request)
        return {"jarm": "abc", "resolved_ip": "1.2.3.4", "error": None}
    monkeypatch.setattr(vm_proxy, "_ssh_json_rpc", fake_rpc)
    result = vm_proxy.probe_win("example.com", 443)
    assert captured == {"action": "jarm_probe", "target": "example.com", "port": 443}
    assert result["jarm"] == "abc"
