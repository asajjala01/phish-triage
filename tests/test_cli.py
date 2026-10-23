import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from phish_triage import cli
from phish_triage.cli import app, render_text
from phish_triage.parser import parse_file

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


def analyze(*args: str) -> tuple[int, str, str]:
    result = runner.invoke(app, ["analyze", *args])
    return result.exit_code, result.stdout, result.stderr


def finding_ids(output: str) -> list[str]:
    return re.findall(r"^\s+\[\w+\]\s+(\w+)", output, re.MULTILINE)


# --- the Phase 1 screenshot case ---


def test_spoofed_email_is_caught() -> None:
    code, out, _ = analyze(str(FIXTURES / "spoofed.eml"))
    assert code == 0
    assert finding_ids(out) == [
        "AUTH_DMARC_FAIL",  # HIGH first
        "SENDER_REPLY_TO_MISMATCH",
        "AUTH_SPF_FAIL",
        "RECEIVED_ORIGIN",  # INFO last
    ]
    assert "spf=fail  dkim=none  dmarc=fail" in out
    assert "Origin: 203[.]0[.]113[.]66" in out


def test_clean_email_has_only_the_origin() -> None:
    code, out, _ = analyze(str(FIXTURES / "clean.eml"))
    assert code == 0
    assert finding_ids(out) == ["RECEIVED_ORIGIN"]
    assert "spf=pass  dkim=pass  dmarc=pass" in out


def test_hops_are_listed_oldest_first() -> None:
    _, out, _ = analyze(str(FIXTURES / "received_chain.eml"))
    path = out.split("Path (oldest first):")[1].split("Origin:")[0]
    assert path.index("webmail") < path.index("out[.]example[.]net") < path.index("store")


# --- safety rule 5: defanged unless asked otherwise ---


def test_output_is_defanged_by_default() -> None:
    _, out, _ = analyze(str(FIXTURES / "spoofed.eml"))
    assert "paypal[.]com" in out
    assert not re.search(r"\w\.(com|net|org)\b", out)  # no live domain anywhere
    assert not re.search(r"\d+\.\d+\.\d+\.\d+", out)  # no live IPv4 anywhere


def test_no_defang_flag_shows_raw_values() -> None:
    _, out, _ = analyze(str(FIXTURES / "spoofed.eml"), "--no-defang")
    assert "service@paypal.com" in out
    assert "203.0.113.66" in out
    assert "[.]" not in out


# --- bad input never crashes ---


def test_malformed_email_is_reported_not_crashed() -> None:
    code, out, _ = analyze(str(FIXTURES / "malformed_boundary.eml"))
    assert code == 0
    assert "PARSE_DEFECT" in out


def test_non_email_file_is_reported(tmp_path: Path) -> None:
    junk = tmp_path / "junk.eml"
    junk.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00not an email")
    code, out, _ = analyze(str(junk))
    assert code == 0
    assert "NOT_AN_EMAIL" in out
    assert "Authentication: no Authentication-Results header" in out
    assert "(no Received headers)" in out


def test_unreadable_auth_header_is_reported(tmp_path: Path) -> None:
    eml = tmp_path / "broken_ar.eml"
    eml.write_bytes(
        b"Authentication-Results: mx.example.org; spf=pass (broken\nFrom: a@b.example\n\nx\n"
    )
    _, out, _ = analyze(str(eml))
    assert "Authentication: the topmost header couldn't be read" in out


# --- errors: clear message, non-zero exit ---


def test_missing_file() -> None:
    code, _, _ = analyze(str(FIXTURES / "does-not-exist.eml"))
    assert code == 2  # Typer's usage error


def test_directory_is_refused() -> None:
    code, _, _ = analyze(str(FIXTURES))
    assert code == 2


def test_bad_brands_file(tmp_path: Path) -> None:
    brands = tmp_path / "brands.yaml"
    brands.write_text("brands: not-a-list\n")
    code, out, err = analyze(str(FIXTURES / "clean.eml"), "--brands", str(brands))
    assert code == 1
    assert "can't load brands" in err
    assert out == ""  # nothing half-printed


def test_missing_brands_file(tmp_path: Path) -> None:
    code, _, err = analyze(str(FIXTURES / "clean.eml"), "--brands", str(tmp_path / "nope.yaml"))
    assert code == 1
    assert "can't load brands" in err


def test_file_unreadable_after_the_existence_check(monkeypatch: pytest.MonkeyPatch) -> None:
    # Typer checks the file first; it can still vanish or lose permissions before the read.
    def denied(path: Path) -> None:
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(cli, "parse_file", denied)
    code, out, err = analyze(str(FIXTURES / "clean.eml"))
    assert code == 1
    assert "can't read" in err
    assert out == ""


def test_render_text_with_no_findings() -> None:
    # Every email gets a Received finding today, so test the renderer directly.
    out = render_text("x.eml", parse_file(FIXTURES / "clean.eml"), [])
    assert out.endswith("Findings: none")


def test_help() -> None:
    result = runner.invoke(app, ["analyze", "--help"])
    assert result.exit_code == 0
    # Help is rendered by rich, which turns color on in CI (GitHub Actions) and splits
    # "--no-defang" into separately colored pieces. Strip the color codes first.
    plain = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    assert "--no-defang" in plain
