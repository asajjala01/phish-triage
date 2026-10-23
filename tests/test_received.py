from datetime import UTC, datetime
from pathlib import Path

import pytest

from phish_triage.headers import analyze_received, check_received, parse_received
from phish_triage.models import Finding, ReceivedChain
from phish_triage.parser import parse_bytes, parse_file

FIXTURES = Path(__file__).parent / "fixtures"


def chain(fixture: str) -> ReceivedChain:
    return analyze_received(parse_file(FIXTURES / fixture))


def origin_ip(fixture: str) -> str | None:
    origin = chain(fixture).origin
    return origin.from_ip if origin else None


def check(fixture: str) -> list[Finding]:
    return check_received(parse_file(FIXTURES / fixture))


# --- parsing one hop, across mail servers ---


def test_postfix() -> None:
    hop = parse_received(
        "from mail.example.com (mail.example.com [203.0.113.10]) by mx.example.org (Postfix)"
        " with ESMTPS id 4ABC for <a@example.org>; Fri, 23 Oct 2026 09:15:01 +0000"
    )
    assert hop.from_helo == "mail.example.com"
    assert hop.from_rdns == "mail.example.com"
    assert hop.rdns_verified
    assert hop.from_ip == "203.0.113.10"
    assert hop.by_host == "mx.example.org"
    assert hop.protocol == "ESMTPS"
    assert hop.timestamp == datetime(2026, 10, 23, 9, 15, 1, tzinfo=UTC)


def test_helo_ip_is_not_mistaken_for_the_connection_ip() -> None:
    # "[192.0.2.250]" is what the sender typed as HELO; the real connection is in the comment.
    hop = parse_received("from [192.0.2.250] (unknown [203.0.113.99]) by mx.example.org")
    assert hop.from_ip == "203.0.113.99"
    assert hop.from_rdns is None  # "unknown" means the lookup failed
    assert not hop.rdns_verified


def test_sendmail_may_be_forged_is_unverified() -> None:
    hop = parse_received(
        "from mail.example.org (mail.example.org [203.0.113.98] (may be forged))"
        " by mx.example.org with ESMTP id 1"
    )
    assert hop.from_rdns == "mail.example.org"  # kept so the analyst sees the claim
    assert not hop.rdns_verified


def test_exim_keyword_inside_comment_is_ignored() -> None:
    # "(envelope-from <...>)" contains "from" but must not start a new section.
    hop = parse_received(
        "from [203.0.113.10] (helo=mail.example.com) by mx.example.org with esmtps (TLS1.3)"
        " (Exim 4.96) (envelope-from <a@example.com>) id 1abc for b@example.org;"
        " Fri, 23 Oct 2026 09:15:01 +0000"
    )
    assert hop.from_ip == "203.0.113.10"  # Exim writes the real IP outside the comment
    assert hop.by_host == "mx.example.org"
    assert hop.protocol == "esmtps"


def test_gmail_trailing_dot_on_rdns() -> None:
    hop = parse_received(
        "from mail.example.com (mail.example.com. [203.0.113.10]) by mx.google.com"
        " with ESMTPS id x12; Fri, 23 Oct 2026 09:15:01 -0700 (PDT)"
    )
    assert hop.from_rdns == "mail.example.com"
    assert hop.timestamp is not None and hop.timestamp.utcoffset() is not None


def test_microsoft_365_bare_ipv6() -> None:
    hop = parse_received(
        "from BN8PR04MB1234.namprd04.prod.outlook.com (2603:10b6:408:ec::30)"
        " by MN2PR04MB5678.namprd04.prod.outlook.com (2603:10b6:208:1::10)"
        " with Microsoft SMTP Server (version=TLS1_2) id 15.20.7000.1;"
        " Fri, 23 Oct 2026 09:15:01 +0000"
    )
    assert hop.from_ip == "2603:10b6:408:ec::30"
    assert hop.by_host == "MN2PR04MB5678.namprd04.prod.outlook.com"
    assert hop.from_rdns is None  # Exchange records no rDNS, so this hop is IP-only


def test_ipv6_literal() -> None:
    hop = parse_received("from m (m.example.com [IPv6:2001:db8::25]) by mx.example.org")
    assert hop.from_ip == "2001:db8::25"


@pytest.mark.parametrize(
    "value",
    [
        "by webmail.example.net with HTTP; Fri, 23 Oct 2026 09:14:00 +0000",  # no from at all
        "complete nonsense here",
        "",
    ],
)
def test_no_connection_ip(value: str) -> None:
    assert parse_received(value).from_ip is None


def test_bad_date_is_none_not_a_crash() -> None:
    assert parse_received("from a (a.example.com [203.0.113.1]) by b; not a date").timestamp is None


# --- the chain: order and origin ---


def test_hops_are_in_travel_order() -> None:
    hops = chain("received_chain.eml").hops
    assert [hop.by_host for hop in hops] == [
        "webmail.example.net",  # bottom header: where the email started
        "out.example.net",
        "mx.example.org",
        "store.example.org",  # top header: the last hop, on our side
    ]


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("received_chain.eml", "198.51.100.25"),  # private hops on both sides skipped
        ("clean.eml", "203.0.113.10"),  # mail.example.org -> mx.example.org is internal
        ("received_forged_bottom.eml", "198.51.100.25"),  # fake "mail.paypal.com" hop ignored
        ("received_helo_spoof.eml", "203.0.113.99"),  # HELO claims our domain, rDNS unknown
        ("received_rdns_forged.eml", "203.0.113.98"),  # rDNS claims our domain, may be forged
        ("received_internal_only.eml", None),
        ("received_missing.eml", None),
    ],
)
def test_origin(fixture: str, expected: str | None) -> None:
    assert origin_ip(fixture) == expected


def test_hop_without_a_connection_ip_is_skipped() -> None:
    # Gmail's topmost hop is internal and has no "from"; the origin is the hop below it.
    raw = (
        b"Received: by 2002:a05:6a10:1234::1 with SMTP id abc;"
        b" Fri, 23 Oct 2026 09:15:02 -0700\n"
        b"Received: from mail.example.com (mail.example.com. [203.0.113.10])"
        b" by mx.google.com with ESMTPS id x12; Fri, 23 Oct 2026 09:15:01 -0700\n"
        b"From: a@example.com\n\nbody\n"
    )
    origin = analyze_received(parse_bytes(raw)).origin
    assert origin is not None and origin.from_ip == "203.0.113.10"


# --- findings ---


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("received_chain.eml", ["RECEIVED_ORIGIN"]),
        ("received_internal_only.eml", ["RECEIVED_ORIGIN_UNKNOWN"]),
        ("received_missing.eml", ["RECEIVED_MISSING"]),
    ],
)
def test_findings(fixture: str, expected: list[str]) -> None:
    assert [f.id for f in check(fixture)] == expected


def test_origin_evidence_with_verified_rdns() -> None:
    [finding] = check("received_chain.eml")
    assert finding.evidence == "198.51.100.25 (out.example.net) -> mx.example.org"


def test_origin_evidence_flags_an_unverified_name() -> None:
    [finding] = check("received_rdns_forged.eml")
    assert finding.evidence == "203.0.113.98 (unverified name mail.example.org) -> mx.example.org"


def test_origin_evidence_falls_back_to_helo() -> None:
    [finding] = check("received_helo_spoof.eml")
    assert finding.evidence == "203.0.113.99 (unverified name mx.example.org) -> mx.example.org"
