"""probe_helper's nmap action with extra ports. The helper runs standalone
on the VM; it is loaded from its file and nmap itself is never executed."""
from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

_SERVICES = """\
# Fields: name port/proto frequency
http\t80/tcp\t0.484143
domain\t53/udp\t0.213496
telnet\t23/tcp\t0.221265
https\t443/tcp\t0.208669
ssh\t22/tcp\t0.182286
ftp\t21/tcp\t0.197667
"""

_XML = """<?xml version="1.0"?><nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="8787"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="443"><state state="closed"/></port>
</ports></host></nmaprun>"""


@pytest.fixture
def ph(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("probe_helper", REPO / "probe_vm" / "probe_helper.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    services = tmp_path / "nmap-services"
    services.write_text(_SERVICES)
    monkeypatch.setattr(mod, "NMAP_SERVICES", services)
    monkeypatch.setattr(mod, "resolve_target_ip", lambda t: "203.0.113.7")
    return mod


def _capture(monkeypatch, mod):
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=_XML, stderr="")
    monkeypatch.setattr(mod.subprocess, "run", run)
    return calls


def test_top_tcp_ports_ranks_by_frequency_and_skips_udp(ph):
    assert ph._top_tcp_ports(3, ph.NMAP_SERVICES) == [80, 23, 443]


def test_extra_ports_are_added_to_the_top_list_not_substituted(ph, monkeypatch):
    calls = _capture(monkeypatch, ph)
    r = ph.action_nmap({"target": "203.0.113.7", "top": 3, "sv": False, "ports": [8787, 443]})
    cmd = calls[0]
    assert "--top-ports" not in cmd
    assert cmd[cmd.index("-p") + 1] == "23,80,443,8787"
    assert r["extra_ports"] == [443, 8787]
    assert [p["port"] for p in r["ports"]] == [22, 8787]


def test_without_extra_ports_the_command_is_unchanged(ph, monkeypatch):
    calls = _capture(monkeypatch, ph)
    r = ph.action_nmap({"target": "203.0.113.7", "top": 100, "sv": True})
    assert calls[0][:3] == ["nmap", "--top-ports", "100"]
    assert r["extra_ports"] == []


@pytest.mark.parametrize("ports", [[0], [65536], list(range(1, 70))])
def test_bad_extra_ports_are_refused_before_scanning(ph, monkeypatch, ports):
    calls = _capture(monkeypatch, ph)
    r = ph.action_nmap({"target": "203.0.113.7", "ports": ports})
    assert r["error"].startswith("bad ports")
    assert calls == []
