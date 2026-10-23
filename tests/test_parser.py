from email.policy import EmailPolicy
from pathlib import Path

import pytest

from phish_triage.models import Attachment, ParsedEmail
from phish_triage.parser import parse_bytes, parse_file

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> ParsedEmail:
    return parse_file(FIXTURES / name)


def finding_ids(parsed: ParsedEmail) -> list[str]:
    return [f.id for f in parsed.findings]


# --- clean email: everything extracted, nothing flagged ---


def test_clean_email_has_no_findings() -> None:
    assert load("clean.eml").findings == []


def test_clean_email_bodies() -> None:
    parsed = load("clean.eml")
    assert parsed.subject == "Your October invoice"
    assert parsed.text_body is not None and "invoice is attached" in parsed.text_body
    assert parsed.html_body is not None and "<p>" in parsed.html_body


def test_clean_email_attachment_decoded_in_memory() -> None:
    [attachment] = load("clean.eml").attachments
    assert attachment.filename == "invoice.pdf"
    assert attachment.content_type == "application/pdf"
    assert attachment.data == b"This is a harmless test file, not a real PDF.\n"
    assert attachment.size == len(attachment.data)


def test_headers_keep_order_and_duplicates() -> None:
    parsed = load("clean.eml")
    received = parsed.get_headers("Received")
    assert len(received) == 2
    assert "by mx.example.org" in received[0]  # topmost = added last, by our own server
    assert "by mail.example.org" in received[1]


def test_get_headers_is_case_insensitive() -> None:
    parsed = load("clean.eml")
    assert parsed.get_headers("authentication-results") == parsed.get_headers(
        "Authentication-Results"
    )
    assert parsed.get_headers("X-Not-There") == []


# --- malformed input: never crash, always explain ---


def test_broken_boundary_is_a_finding_not_a_crash() -> None:
    parsed = load("malformed_boundary.eml")
    assert "PARSE_DEFECT" in finding_ids(parsed)
    assert any("StartBoundaryNotFoundDefect" in f.evidence for f in parsed.findings)
    assert parsed.subject == "Broken boundary"  # headers still usable


def test_unknown_charset_falls_back_and_keeps_the_body() -> None:
    parsed = load("unknown_charset.eml")
    [finding] = parsed.findings
    assert finding.id == "UNKNOWN_CHARSET"
    assert finding.evidence == "x-no-such-charset"
    assert parsed.text_body is not None and "doesn't exist" in parsed.text_body


def test_mangled_from_header_is_flagged() -> None:
    parsed = load("mangled_from.eml")
    defects = [f for f in parsed.findings if f.id == "HEADER_DEFECT"]
    assert defects and all(f.evidence.startswith("From:") for f in defects)
    assert parsed.text_body is not None  # the rest of the email still parses


def test_unparseable_header_is_kept_raw(monkeypatch: pytest.MonkeyPatch) -> None:
    # No fixture reliably makes the stdlib header parser raise, so simulate it.
    original = EmailPolicy.header_fetch_parse

    def explode_on_subject(self: EmailPolicy, name: str, value: str) -> object:
        if name.lower() == "subject":
            raise ValueError("simulated parser bug")
        return original(self, name, value)

    monkeypatch.setattr(EmailPolicy, "header_fetch_parse", explode_on_subject)
    parsed = load("clean.eml")
    assert finding_ids(parsed) == ["HEADER_UNPARSEABLE"]
    assert parsed.subject == "Your October invoice"  # raw value kept
    assert len(parsed.get_headers("Received")) == 2  # other headers unaffected


@pytest.mark.parametrize("data", [b"", b"\x89PNG\r\n\x1a\n\x00\x00not an email at all\n"])
def test_non_email_input_is_flagged(data: bytes) -> None:
    parsed = parse_bytes(data)
    assert "NOT_AN_EMAIL" in finding_ids(parsed)
    assert parsed.headers == []


def test_valid_email_is_not_flagged_as_non_email() -> None:
    assert "NOT_AN_EMAIL" not in finding_ids(load("mangled_from.eml"))


# --- forwarded email: one opaque attachment, never the outer body ---


def test_forward_is_one_attachment() -> None:
    parsed = load("forwarded.eml")
    assert parsed.findings == []
    assert parsed.text_body is not None and "see attached" in parsed.text_body
    assert parsed.html_body is None  # the inner HTML must not leak out as our body
    [forward] = parsed.attachments  # inner note.txt is inside the forward, not listed on its own
    assert forward.filename == "original.eml"
    assert forward.content_type == "message/rfc822"
    assert b"Subject: inner message" in forward.data


# --- misc ---


def test_attachment_bytes_stay_out_of_repr() -> None:
    attachment = Attachment(filename="a.bin", content_type="application/octet-stream", data=b"x")
    assert "data=" not in repr(attachment)


def test_missing_file_raises() -> None:
    with pytest.raises(FileNotFoundError):
        parse_file(FIXTURES / "does-not-exist.eml")
