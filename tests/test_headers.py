from email.headerregistry import HeaderRegistry
from pathlib import Path

import pytest

from phish_triage.config import load_brands
from phish_triage.headers import check_sender, org_domain
from phish_triage.models import Brand, Finding
from phish_triage.parser import parse_bytes, parse_file

FIXTURES = Path(__file__).parent / "fixtures"
# Fixture tests run against the real shipped brand list, so it gets tested too.
BRANDS = load_brands(Path(__file__).parent.parent / "config" / "brands.yaml")


def check(fixture: str) -> list[Finding]:
    return check_sender(parse_file(FIXTURES / fixture), BRANDS)


def sender_ids(fixture: str) -> list[str]:
    return [f.id for f in check(fixture)]


# --- org_domain: compare organizations, not exact hostnames ---


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("example.com", "example.com"),
        ("mail.example.com", "example.com"),
        ("EXAMPLE.COM.", "example.com"),  # case and trailing dot ignored
        ("a.b.example.co.uk", "example.co.uk"),  # "last two labels" would say co.uk
        ("bounces.amazonses.com", "amazonses.com"),
        ("someone.github.io", "someone.github.io"),  # each github.io site is its own org
        ("[192.0.2.1]", "[192.0.2.1]"),  # IP literal kept as-is
        ("localhost", "localhost"),
    ],
)
def test_org_domain(domain: str, expected: str) -> None:
    assert org_domain(domain) == expected


# --- one fixture per finding: each triggers exactly its own ---


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("reply_to_mismatch.eml", ["SENDER_REPLY_TO_MISMATCH"]),
        ("return_path_mismatch.eml", ["SENDER_RETURN_PATH_MISMATCH"]),
        ("multiple_from.eml", ["SENDER_MULTIPLE_FROM"]),
        ("missing_from.eml", ["SENDER_FROM_MISSING"]),
        ("mangled_from.eml", ["SENDER_FROM_MISSING"]),  # From present, but no domain in it
        ("display_name_brand.eml", ["SENDER_DISPLAY_NAME_BRAND"]),
        ("display_name_address.eml", ["SENDER_DISPLAY_NAME_ADDRESS"]),
    ],
)
def test_fixture_triggers_its_finding(fixture: str, expected: list[str]) -> None:
    assert sender_ids(fixture) == expected


def test_unparseable_from_is_missing_not_a_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    # No fixture reliably makes the stdlib header parser raise, so simulate it.
    original = HeaderRegistry.__call__

    def explode_on_from(self: HeaderRegistry, name: str, value: str) -> object:
        if name.lower() == "from":
            raise ValueError("simulated parser bug")
        return original(self, name, value)

    monkeypatch.setattr(HeaderRegistry, "__call__", explode_on_from)
    assert sender_ids("clean.eml") == ["SENDER_FROM_MISSING"]


# --- and fixtures that must stay quiet ---


@pytest.mark.parametrize(
    "fixture",
    [
        "clean.eml",
        "subdomain_same_org.eml",  # help.example.co.uk, mail.example.co.uk: same org
        "null_return_path.eml",  # <> is a normal bounce, not a mismatch
        "forwarded.eml",  # the inner email's sender must not be checked as ours
        "display_name_legit_brand.eml",  # "PayPal" really from paypal.com
    ],
)
def test_fixture_has_no_sender_findings(fixture: str) -> None:
    assert sender_ids(fixture) == []


# --- evidence: an analyst can see exactly what didn't match ---


def test_reply_to_evidence_names_both_addresses() -> None:
    [finding] = check("reply_to_mismatch.eml")
    assert finding.evidence == "From: billing@example.com -> Reply-To: billing-dept@example.net"


def test_multiple_from_evidence_lists_every_from() -> None:
    [finding] = check("multiple_from.eml")
    assert "it@example.com" in finding.evidence
    assert "it-support@example.net" in finding.evidence


def test_display_name_evidence_shows_name_and_real_address() -> None:
    [finding] = check("display_name_brand.eml")
    assert finding.evidence == '"PayPal Security" <service@example.net>'
    assert "PayPal" in finding.description


# --- brand matching: whole words, any configured name ---

TEST_BRANDS = [Brand(name="Apple", domains=("apple.com",), aliases=("iCloud",))]


def from_line(from_header: str) -> list[str]:
    raw = f"From: {from_header}\nSubject: t\n\nbody\n".encode()
    return [f.id for f in check_sender(parse_bytes(raw), TEST_BRANDS)]


@pytest.mark.parametrize(
    "from_header",
    [
        '"Apple" <id@example.net>',
        '"APPLE SUPPORT" <id@example.net>',  # case-insensitive
        '"Your iCloud storage is full" <id@example.net>',  # alias
        '"Apple." <id@example.net>',  # punctuation is a word boundary
    ],
)
def test_brand_named_from_wrong_domain(from_header: str) -> None:
    assert from_line(from_header) == ["SENDER_DISPLAY_NAME_BRAND"]


@pytest.mark.parametrize(
    "from_header",
    [
        '"Applebee\'s" <deals@example.net>',  # brand is only part of a word
        '"Pineapple Co" <hi@example.net>',
        '"Apple" <noreply@email.apple.com>',  # brand's own subdomain
        '"Example Team" <team@example.net>',  # no brand at all
    ],
)
def test_no_brand_finding(from_header: str) -> None:
    assert from_line(from_header) == []


def test_display_name_address_from_same_org_is_fine() -> None:
    assert from_line('"billing@example.com" <billing@mail.example.com>') == []


def test_no_brands_configured_skips_brand_check() -> None:
    raw = b'From: "PayPal" <x@example.net>\nSubject: t\n\nbody\n'
    assert check_sender(parse_bytes(raw), []) == []
