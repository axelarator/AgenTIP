"""JA4X, computed from certificates - cti/sources/ja4x.py.

Known-answer vectors are from FoxIO's canonical Rust implementation
(rust/ja4x: hash12). The generated certificate's expected value is built by
hand from its OID bytes, so the test does not lean on the code under test.
"""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cti.sources import ja4x, observe


def _cert():
    """Self-signed, the shape of a stock C2 cert: C, O, CN; two extensions."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyOrg"),
                      x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime(2026, 10, 1)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))


def _h(s):
    return hashlib.sha256(s.encode()).hexdigest()[:12]


# C = 2.5.4.6 -> 550406, O = 2.5.4.10 -> 55040a, CN = 2.5.4.3 -> 550403;
# basicConstraints 2.5.29.19 -> 551d13, subjectAltName 2.5.29.17 -> 551d11
EXPECTED = f"{_h('550406,55040a,550403')}_{_h('550406,55040a,550403')}_{_h('551d13,551d11')}"


@pytest.mark.parametrize("oid,hexed", [
    ("2.5.4.3", "550403"), ("2.5.29.19", "551d13"),
    ("1.2.840.113549.1.9.1", "2a864886f70d010901"),
    ("1.3.6.1.4.1.11129.2.4.2", "2b06010401d679020402"),
])
def test_oid_hex(oid, hexed):
    assert ja4x.oid_hex(oid) == hexed


def test_hash12_matches_foxio_and_zero_fills_empty():
    assert ja4x.hash12("551d0f,551d25,551d11") == "aae71e8db6d7"
    assert ja4x.hash12("") == "000000000000"


def test_a_certificate_from_pem_and_der_agree_with_the_hand_built_value():
    cert = _cert()
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    der = cert.public_bytes(serialization.Encoding.DER)
    assert ja4x.from_pem(pem) == EXPECTED
    assert ja4x.from_der(der) == EXPECTED
    assert ja4x.for_tls({"der_b64": base64.b64encode(der).decode()}) == EXPECTED


def test_garbage_is_none_not_an_exception():
    assert ja4x.from_pem("not a certificate") is None
    assert ja4x.for_tls({"der_b64": "!!"}) is None
    assert ja4x.for_tls({}) is None


def test_the_observe_pass_yields_tls_ja4x():
    pem = _cert().public_bytes(serialization.Encoding.PEM).decode()
    found = dict(observe.selectors_from({"tls": {"cert_sha256": "a" * 64, "pem": pem}},
                                        target="x.example", kind="domain"))
    assert found["tls.ja4x"] == EXPECTED


def test_netwatch_records_ja4x_and_drops_the_pem():
    from cti import store
    from cti.netwatch import ingest, jobs
    import json
    pem = _cert().public_bytes(serialization.Encoding.PEM).decode()
    rec = {"scan_id": "sX", "ts": "2026-10-17T15:00:00+00:00", "vantage": "probe",
           "profile": "hot", "target": "203.0.113.40", "ip": "203.0.113.40", "port": 443,
           "open": True, "tls": {"cert_sha256": "b" * 64, "pem": pem}}
    (jobs.spool_dir() / "sX.jsonl").write_text(json.dumps(rec))
    ingest.ingest(client=None)
    with store.connect(read_only=True) as con:
        ja4x_col, record = con.execute("SELECT ja4x, record FROM service_snapshots "
                                       "WHERE target='203.0.113.40'").fetchone()
        sel = con.execute("SELECT selector_value FROM selectors WHERE "
                          "selector_type='tls.ja4x' AND indicator_value='203.0.113.40'").fetchone()
    assert ja4x_col == EXPECTED and sel == (EXPECTED,)
    assert "pem" not in (json.loads(record).get("tls") or {})


def test_win116_records_ja4x_and_drops_the_der(monkeypatch):
    from cti import store
    from cti.netwatch import win116
    from cti.probe import win_proxy
    import json
    monkeypatch.setenv("CTI_WIN_HOST", "192.0.2.16")
    monkeypatch.setenv("CTI_WIN_USER", "client")
    der = base64.b64encode(_cert().public_bytes(serialization.Encoding.DER)).decode()
    monkeypatch.setattr(win_proxy, "fetch", lambda reqs, timeout=15: [
        win_proxy.shape({"target": r["target"], "url": r["url"], "status": 200, "title": "t",
                         "cert": {"sha256": "c" * 64, "subject_dn": "CN=localhost",
                                  "der_b64": der}}) for r in reqs])
    win116.run(targets=[{"value": "x.example", "kind": "domain", "ports": [],
                         "actor": "A", "lifecycle": "active"}])
    with store.connect(read_only=True) as con:
        rows = con.execute("SELECT ja4x, record FROM service_snapshots WHERE vantage='win116'").fetchall()
    assert all(r[0] == EXPECTED for r in rows)
    assert all("der_b64" not in (json.loads(r[1]).get("tls") or {}) for r in rows)
