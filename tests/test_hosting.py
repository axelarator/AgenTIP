"""Shared-hosting verdicts - cti/store/hosting.py."""
from __future__ import annotations

from cti.store import hosting
from cti.tracking.analytics import SHARED_HOSTING_ASNS


def test_the_original_three_asns_are_still_shared():
    assert {16509, 45102, 13335} <= set(hosting.shared_asns())
    assert SHARED_HOSTING_ASNS == hosting.shared_asns()


def test_bulk_web_hosts_are_shared_and_vps_providers_are_not():
    assert hosting.is_shared(asn=47583)[0]          # Hostinger
    assert hosting.is_shared(asn=26496)[0]          # GoDaddy
    # Actors rent dedicated boxes here; an ASN-wide rule would hide them.
    for vps in (16276, 24940, 14061):               # OVH, Hetzner, DigitalOcean
        assert not hosting.is_shared(asn=vps)[0]


def test_a_cdn_ptr_is_shared_whatever_the_asn():
    shared, why = hosting.is_shared(asn=64500, ptr="ec2-1-2-3-4.cloudfront.net")
    assert shared and "PTR" in why


def test_many_hostnames_alone_do_not_make_an_address_shared():
    """208.91.112.55 carried 48 hostnames and was STAC4749's own box."""
    entry = {"asn": 40934, "ip_hostnames": [f"h{i}.example" for i in range(60)]}
    assert hosting.entry_shared(entry) == (False, None)


def test_the_entry_verdict_reads_what_the_sweep_stamped():
    assert hosting.entry_shared({"shared_hosting": "PTR x"}) == (True, "PTR x")
