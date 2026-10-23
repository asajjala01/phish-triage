from pathlib import Path

import pytest

from phish_triage.headers import check_auth, parse_authentication_results
from phish_triage.models import AuthResult, Finding
from phish_triage.parser import parse_bytes, parse_file

FIXTURES = Path(__file__).parent / "fixtures"


def check(fixture: str) -> list[Finding]:
    return check_auth(parse_file(FIXTURES / fixture))


def auth_ids(fixture: str) -> list[str]:
    return [f.id for f in check(fixture)]


def methods(value: str) -> list[str]:
    parsed = parse_authentication_results(value)
    assert parsed is not None
    return [str(result) for result in parsed.results]


# --- the parser: comments, quotes and odd formatting ---


def test_parses_authserv_id_and_each_method() -> None:
    parsed = parse_authentication_results(
        "mx.example.org; spf=pass smtp.mailfrom=a@example.com; dkim=pass header.d=example.com"
    )
    assert parsed is not None
    assert parsed.authserv_id == "mx.example.org"
    assert parsed.results == (
        AuthResult("spf", "pass", (("smtp.mailfrom", "a@example.com"),)),
        AuthResult("dkim", "pass", (("header.d", "example.com"),)),
    )


def test_semicolons_inside_nested_comments_dont_split() -> None:
    value = "mx.example.org; spf=fail (comment; with (nested) semicolon) smtp.mailfrom=example.net"
    assert methods(value) == ["spf=fail smtp.mailfrom=example.net"]


def test_semicolons_inside_quotes_dont_split() -> None:
    value = 'mx.example.org; dkim=fail reason="bad; sig" header.d=example.com'
    assert methods(value) == ["dkim=fail reason=bad; sig header.d=example.com"]


def test_escaped_quote_inside_quotes() -> None:
    value = r'mx.example.org; dkim=fail reason="said \"no\"; really" header.d=example.com'
    assert methods(value) == [r"dkim=fail reason=said \"no\"; really header.d=example.com"]


def test_escaped_paren_inside_comment() -> None:
    value = r"mx.example.org; spf=pass (escaped \) paren) smtp.mailfrom=example.com"
    assert methods(value) == ["spf=pass smtp.mailfrom=example.com"]


def test_case_spaces_and_version_suffixes_are_normalized() -> None:
    assert methods("mx.example.org 1; DKIM/1 = PASS header.d=example.com") == [
        "dkim=pass header.d=example.com"
    ]


def test_none_means_no_results() -> None:
    parsed = parse_authentication_results("mx.example.org; none")
    assert parsed is not None
    assert parsed.authserv_id == "mx.example.org"
    assert parsed.results == ()


def test_missing_authserv_id_is_accepted() -> None:
    # Microsoft 365 writes the header without one.
    parsed = parse_authentication_results("spf=pass smtp.mailfrom=example.com;dmarc=pass")
    assert parsed is not None
    assert parsed.authserv_id == ""
    assert [str(result) for result in parsed.results] == [
        "spf=pass smtp.mailfrom=example.com",
        "dmarc=pass",
    ]


@pytest.mark.parametrize(
    "value",
    [
        "",
        "mx.example.org",  # an id but no results
        "mx.example.org; spf",  # method with no result
        "mx.example.org; spf=pass (unclosed comment",
        'mx.example.org; spf=pass reason="unclosed quote',
    ],
)
def test_malformed_values_return_none(value: str) -> None:
    assert parse_authentication_results(value) is None


# --- one fixture per finding ---


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("spf_fail.eml", ["AUTH_SPF_FAIL"]),
        ("dkim_fail.eml", ["AUTH_DKIM_FAIL"]),
        ("dmarc_fail.eml", ["AUTH_DMARC_FAIL"]),
        ("auth_missing.eml", ["AUTH_RESULTS_MISSING"]),
        ("auth_microsoft365.eml", ["AUTH_SPF_FAIL", "AUTH_DMARC_FAIL"]),
    ],
)
def test_fixture_triggers_its_finding(fixture: str, expected: list[str]) -> None:
    assert auth_ids(fixture) == expected


@pytest.mark.parametrize("fixture", ["clean.eml", "auth_comments.eml"])
def test_fixture_has_no_auth_findings(fixture: str) -> None:
    assert auth_ids(fixture) == []


# --- the roadmap rule: only the topmost header counts ---


def test_forged_pass_below_the_real_header_is_ignored() -> None:
    # Our server said dmarc=fail on top; an attacker-written "all pass" sits below it.
    assert auth_ids("forged_lower_ar.eml") == ["AUTH_DMARC_FAIL"]


def test_failures_below_a_passing_top_header_are_ignored() -> None:
    assert auth_ids("forged_lower_ar_reverse.eml") == []


# --- evidence says who vouched ---


def test_evidence_names_the_authserv_id() -> None:
    [finding] = check("spf_fail.eml")
    assert finding.evidence == "mx.example.org: spf=fail smtp.mailfrom=billing@example.com"


def test_evidence_without_authserv_id_says_unknown_server() -> None:
    finding = check("auth_microsoft365.eml")[0]
    assert finding.evidence.startswith("unknown server: spf=fail")


# --- smaller rules, on inline headers ---


def header(value: str) -> list[str]:
    raw = f"Authentication-Results: {value}\nFrom: a@example.com\n\nbody\n".encode()
    return [f.id for f in check_auth(parse_bytes(raw))]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("mx.example.org; spf=softfail", ["AUTH_SPF_SOFTFAIL"]),
        ("mx.example.org; dmarc=none", ["AUTH_DMARC_NONE"]),
        ("mx.example.org; spf=temperror", ["AUTH_SPF_ERROR"]),
        ("mx.example.org; dmarc=permerror", ["AUTH_DMARC_ERROR"]),
        ("mx.example.org; dkim=temperror", ["AUTH_DKIM_ERROR"]),
        ("mx.example.org; spf=neutral; dkim=none; dmarc=pass", []),
        ("mx.example.org; none", []),
        ("mx.example.org; spf=pass (broken", ["AUTH_RESULTS_UNPARSEABLE"]),
    ],
)
def test_result_to_finding(value: str, expected: list[str]) -> None:
    assert header(value) == expected


def test_one_passing_dkim_signature_is_enough() -> None:
    value = "mx.example.org; dkim=fail header.d=esp.example.net; dkim=pass header.d=example.com"
    assert header(value) == []


def test_every_failed_dkim_signature_is_in_the_evidence() -> None:
    raw = (
        b"Authentication-Results: mx.example.org; dkim=fail header.d=a.example;"
        b" dkim=fail header.d=b.example\nFrom: x@example.com\n\nbody\n"
    )
    [finding] = check_auth(parse_bytes(raw))
    assert "header.d=a.example" in finding.evidence
    assert "header.d=b.example" in finding.evidence
