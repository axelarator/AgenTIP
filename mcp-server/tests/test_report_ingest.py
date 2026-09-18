from __future__ import annotations

from cti_tools import report_ingest


SAMPLE = """
Fox Tempest Malware Campaign Analysis

Researchers observed Fox Tempest deploying a loader that uses
PowerShell for execution (T1059.001) and scheduled tasks for
persistence (T1053.005).

Observed indicators:
- C2 domain: badactor-c2[.]xyz
- Secondary domain: hxxps://update-service[.]top/beacon
- Malicious IP: 185.220.101.47
- Internal server for comparison: 10.0.0.5 (should be excluded)
- Payload SHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
- Dropper MD5: 098f6bcd4621d373cade4e832627b4f6

Also seen using T1566.001 for initial access via phishing attachments.
"""


def test_defang_normalize():
    assert report_ingest.defang_normalize("hxxps://evil[.]xyz") == "https://evil.xyz"


def test_extract_observables():
    text = report_ingest.defang_normalize(SAMPLE)
    obs = report_ingest.extract_observables(text)
    assert "badactor-c2.xyz" in obs["domains"]
    assert "update-service.top" in obs["domains"]
    assert "185.220.101.47" in obs["ips"]
    assert "10.0.0.5" not in obs["ips"]  # private, filtered
    assert "https://update-service.top/beacon" in obs["urls"]
    assert "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" in obs["hashes"]
    assert "md5:098f6bcd4621d373cade4e832627b4f6" in obs["hashes"]
    assert set(obs["ttps"]) == {"T1059.001", "T1053.005", "T1566.001"}


def test_extract_emails_cves_wallets():
    text = report_ingest.defang_normalize(
        "Operator reachable at admin@badactor-c2[.]xyz, exploiting CVE-2024-1234 "
        "and cve-2023-99999. Ransom to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq "
        "or 0x52908400098527886E0F7030069857D2E4169EE7."
    )
    obs = report_ingest.extract_observables(text)
    assert "admin@badactor-c2.xyz" in obs["emails"]
    assert "CVE-2024-1234" in obs["cves"]
    assert "CVE-2023-99999" in obs["cves"]  # normalized to upper-case
    assert "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" in obs["wallets"]
    assert "0x52908400098527886E0F7030069857D2E4169EE7" in obs["wallets"]


def test_extract_ipv6():
    obs = report_ingest.extract_observables("C2 resolved to 2606:4700:4700::1111 today.")
    assert "2606:4700:4700::1111" in obs["ips"]


def test_extract_ipv6_private_filtered():
    obs = report_ingest.extract_observables("Loopback fe80::1 and ::1 should not count.")
    assert obs["ips"] == []


def test_extract_ip_port_inline():
    obs = report_ingest.extract_observables("C2 beacon seen at 206.238.115.58:886 in traffic.")
    assert obs["ip_ports"] == {"206.238.115.58": [886]}


def test_extract_ip_port_proximity_single_ip():
    obs = report_ingest.extract_observables(
        "RomulusLoader: TCP port 1234 (IP: 43.156.77.97)")
    assert obs["ip_ports"] == {"43.156.77.97": [1234]}


def test_extract_ip_port_proximity_multiple_ips():
    obs = report_ingest.extract_observables(
        "Atlas RAT: TCP port 886 (IPs: 206.238.115.58, 154.211.86.110)")
    assert obs["ip_ports"] == {"206.238.115.58": [886], "154.211.86.110": [886]}


def test_extract_ip_port_two_distinct_mentions():
    obs = report_ingest.extract_observables(
        "Atlas RAT: TCP port 886 (IPs: 206.238.115.58). "
        "RomulusLoader: TCP port 1234 (IP: 43.156.77.97)."
    )
    assert obs["ip_ports"] == {"206.238.115.58": [886], "43.156.77.97": [1234]}


def test_extract_ip_port_no_mention():
    obs = report_ingest.extract_observables("C2 at 185.220.101.47, no port mentioned.")
    assert obs["ip_ports"] == {}


def test_extract_ip_port_out_of_range_ignored():
    obs = report_ingest.extract_observables("Build port 999999 near 185.220.101.47.")
    assert obs["ip_ports"] == {}


def test_extract_ip_port_far_apart_not_associated():
    filler = " lorem ipsum" * 40  # well past _PORT_PROXIMITY_WINDOW
    obs = report_ingest.extract_observables(
        f"Uses TCP port 8443 for staging.{filler} Unrelated IP 185.220.101.47 mentioned later."
    )
    assert obs["ip_ports"] == {}


def test_extract_ip_port_multiple_distinct_ports_same_ip():
    """A genuinely multi-port C2: two separate, individually unambiguous
    mentions of the same IP with different ports should both be kept,
    not just the first one found."""
    obs = report_ingest.extract_observables(
        "Atlas RAT: TCP port 886 (IP: 206.238.115.58). "
        "The same host also serves exfil on TCP port 4444 (IP: 206.238.115.58)."
    )
    assert obs["ip_ports"] == {"206.238.115.58": [886, 4444]}


def test_extract_ip_port_direct_and_proximity_combine_without_duplicating():
    obs = report_ingest.extract_observables(
        "C2 beacon seen at 206.238.115.58:886 in traffic. "
        "The same actor also runs TCP port 886 (IP: 206.238.115.58) for backup C2. "
        "Exfil goes out over TCP port 9090 (IP: 206.238.115.58)."
    )
    assert obs["ip_ports"] == {"206.238.115.58": [886, 9090]}


def test_defang_dot_and_at_variants():
    assert report_ingest.defang_normalize("evil[dot]com") == "evil.com"
    assert report_ingest.defang_normalize("user[at]evil(dot)com") == "user@evil.com"


def test_suggest_cluster_names_single_candidate():
    text = report_ingest.defang_normalize(SAMPLE)
    assert report_ingest.suggest_cluster_names(text) == ["Fox Tempest"]


def test_suggest_cluster_names_none():
    assert report_ingest.suggest_cluster_names("no actor names in this text at all") == []


def test_suggest_cluster_names_mandiant_style():
    text = "UNC4321 has been observed deploying ransomware."
    names = report_ingest.suggest_cluster_names(text)
    assert names == ["UNC4321"]


def test_fetch_text_local_file(tmp_path):
    p = tmp_path / "report.txt"
    p.write_text("hello world")
    assert report_ingest.fetch_text(str(p)) == "hello world"


def test_fetch_text_missing_file():
    import pytest
    with pytest.raises(FileNotFoundError):
        report_ingest.fetch_text("/no/such/file.txt")


def test_fetch_text_pdf_without_poppler(tmp_path, monkeypatch):
    import pytest
    # Simulate poppler not being installed: a PDF then falls back to the
    # instructive UnsupportedSource error instead of extracting.
    monkeypatch.setattr(report_ingest.shutil, "which", lambda name: None)
    p = tmp_path / "report.pdf"
    p.write_bytes(b"%PDF-1.4 not really a pdf")
    with pytest.raises(report_ingest.UnsupportedSource):
        report_ingest.fetch_text(str(p))


def test_fetch_text_pdf_with_poppler(tmp_path):
    import pytest
    import shutil
    if not shutil.which("pdftotext"):
        pytest.skip("pdftotext (poppler-utils) not installed")
    # Minimal single-page PDF that renders the literal text "T1059.001".
    pdf = (b"%PDF-1.1\n"
           b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
           b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
           b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]"
           b"/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n"
           b"4 0 obj<</Length 44>>stream\n"
           b"BT /F1 12 Tf 20 100 Td (T1059.001) Tj ET\n"
           b"endstream endobj\n"
           b"5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n"
           b"trailer<</Root 1 0 R>>\n")
    p = tmp_path / "report.pdf"
    p.write_bytes(pdf)
    assert "T1059.001" in report_ingest.fetch_text(str(p))


def test_html_stripped(tmp_path):
    p = tmp_path / "report.html"
    p.write_text("<html><body><script>ignored()</script><p>Fox Tempest seen "
                  "using T1059.001</p></body></html>")
    text = report_ingest.fetch_text(str(p))
    assert "ignored()" not in text
    assert "Fox Tempest" in text
    assert "T1059.001" in text
