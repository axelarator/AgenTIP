"""JA4X: how a certificate was generated, from the certificate itself.

JA4X fingerprints the *shape* of a certificate - which attributes its issuer
and subject carry, in what order, and which extensions it has - not their
values. Two certificates minted by the same tool or script share it even
when every name in them differs, which is what makes it useful against a C2
framework's or a kit's self-signed certificates (and useless against Let's
Encrypt, where everyone's looks alike: see `tls.ja4x` in selectors.TYPES).

Zeek does not produce it - FoxIO's Zeek script for it is a placeholder
"awaiting Zeek object support", and the sensor's x509.log carries no such
field (checked 2026-10-17) - so it is computed here from the certificate
each vantage already collects: the probe's tlsx PEM, win116's DER.

    ja4x = hash12(issuer attribute OIDs) _ hash12(subject attribute OIDs)
           _ hash12(extension OIDs)

Each list is the OIDs in certificate order, each written as the hex of its
DER content octets (2.5.4.3 -> "550403"), comma-joined; hash12 is the first
12 hex characters of SHA-256, or twelve zeros for an empty list. This
follows FoxIO's canonical Rust implementation (rust/ja4x). JA4X is FoxIO's
design, published under the FoxIO License 1.1 (patent pending); this is an
independent implementation for our own threat-intelligence use.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any

from cryptography import x509

EMPTY = "000000000000"


def _base128(value: int) -> list[int]:
    out = [value & 0x7F]
    value >>= 7
    while value:
        out.insert(0, (value & 0x7F) | 0x80)
        value >>= 7
    return out


def oid_hex(dotted: str) -> str:
    """The DER content octets of an OID, as hex: 2.5.4.3 -> '550403'."""
    arcs = [int(a) for a in dotted.split(".")]
    octets = _base128(arcs[0] * 40 + arcs[1])
    for arc in arcs[2:]:
        octets.extend(_base128(arc))
    return bytes(octets).hex()


def hash12(joined: str) -> str:
    if not joined:
        return EMPTY
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:12]


def raw(cert: x509.Certificate) -> tuple[str, str, str]:
    """The three comma-joined OID lists JA4X hashes (FoxIO's ja4x_r)."""
    def names(name: x509.Name) -> str:
        return ",".join(oid_hex(attr.oid.dotted_string)
                        for rdn in name.rdns for attr in rdn)
    extensions = ",".join(oid_hex(ext.oid.dotted_string) for ext in cert.extensions)
    return names(cert.issuer), names(cert.subject), extensions


def from_cert(cert: x509.Certificate) -> str:
    return "_".join(hash12(part) for part in raw(cert))


def from_pem(pem: str | bytes) -> str | None:
    try:
        data = pem.encode() if isinstance(pem, str) else pem
        return from_cert(x509.load_pem_x509_certificate(data))
    except (ValueError, TypeError):
        return None


def from_der(der: bytes) -> str | None:
    try:
        return from_cert(x509.load_der_x509_certificate(der))
    except (ValueError, TypeError):
        return None


def for_tls(tls: dict[str, Any] | None) -> str | None:
    """JA4X for an observe-shaped `tls` dict: an existing value, else
    computed from the PEM (probe) or base64 DER (win116) it carries."""
    if not tls:
        return None
    if tls.get("ja4x"):
        return tls["ja4x"]
    if tls.get("pem"):
        return from_pem(tls["pem"])
    if tls.get("der_b64"):
        try:
            return from_der(base64.b64decode(tls["der_b64"]))
        except (ValueError, TypeError):
            return None
    return None
