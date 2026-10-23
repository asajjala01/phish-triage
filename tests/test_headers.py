from email.headerregistry import HeaderRegistry
from pathlib import Path

import pytest

from phish_triage.headers import check_sender, org_domain
from phish_triage.parser import parse_file

FIXTURES = Path(__file__).parent / "fixtures"


def sender_ids(fixture: str) -> list[str]:
    return [f.id for f in check_sender(parse_file(FIXTURES / fixture))]


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
    ],
)
def test_fixture_has_no_sender_findings(fixture: str) -> None:
    assert sender_ids(fixture) == []


# --- evidence: an analyst can see exactly what didn't match ---


def test_reply_to_evidence_names_both_addresses() -> None:
    [finding] = check_sender(parse_file(FIXTURES / "reply_to_mismatch.eml"))
    assert finding.evidence == "From: billing@example.com -> Reply-To: billing-dept@example.net"


def test_multiple_from_evidence_lists_every_from() -> None:
    [finding] = check_sender(parse_file(FIXTURES / "multiple_from.eml"))
    assert "it@example.com" in finding.evidence
    assert "it-support@example.net" in finding.evidence
