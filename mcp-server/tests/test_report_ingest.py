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


def test_fetch_text_pdf_unsupported():
    import pytest
    with pytest.raises(report_ingest.UnsupportedSource):
        report_ingest.fetch_text("/tmp/report.pdf")


def test_html_stripped(tmp_path):
    p = tmp_path / "report.html"
    p.write_text("<html><body><script>ignored()</script><p>Fox Tempest seen "
                  "using T1059.001</p></body></html>")
    text = report_ingest.fetch_text(str(p))
    assert "ignored()" not in text
    assert "Fox Tempest" in text
    assert "T1059.001" in text
