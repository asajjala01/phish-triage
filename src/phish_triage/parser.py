"""Turn raw .eml bytes into a ParsedEmail without ever crashing on malformed input.

Python's email parser is lenient: most damage (a broken MIME boundary, a garbled
address) does not raise. It is recorded on each part's `.defects` list and parsing
carries on. So surviving malformed mail mostly means reading those defects and
turning them into findings. The two places that *can* raise are caught explicitly.
"""

from email import policy
from email.errors import HeaderParseError
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

from phish_triage.models import Attachment, Finding, ParsedEmail, Severity


def parse_file(path: Path) -> ParsedEmail:
    """Read an .eml file and parse it. A missing file raises; that's a user error, not bad mail."""
    return parse_bytes(path.read_bytes())


def parse_bytes(data: bytes) -> ParsedEmail:
    # policy.default gives EmailMessage objects: get_body(), get_content() and structured
    # headers. The legacy default (compat32) has none of those.
    msg = BytesParser(policy=policy.default).parsebytes(data)
    parsed = ParsedEmail()

    parsed.headers = _read_headers(msg, parsed.findings)
    if not parsed.headers:
        parsed.findings.append(
            Finding(
                id="NOT_AN_EMAIL",
                severity=Severity.MEDIUM,
                description="No email headers found; this may not be an email at all.",
            )
        )
    subjects = parsed.get_headers("Subject")
    parsed.subject = subjects[0] if subjects else None

    _record_defects(msg, parsed.findings)

    # get_body() picks the best body part and skips anything marked as an attachment.
    # It does not descend into forwarded (message/rfc822) emails, which is what we want:
    # a forward is an attachment, not this email's body.
    text_part = msg.get_body(preferencelist=("plain",))
    html_part = msg.get_body(preferencelist=("html",))
    if text_part is not None:
        parsed.text_body = _read_text(text_part, parsed.findings)
    if html_part is not None:
        parsed.html_body = _read_text(html_part, parsed.findings)

    parsed.attachments = _collect_attachments(msg, body_parts=(text_part, html_part))
    return parsed


def _read_headers(msg: EmailMessage, findings: list[Finding]) -> list[tuple[str, str]]:
    """Decode every header one at a time, so one bad header can't take the rest down."""
    headers: list[tuple[str, str]] = []
    # raw_items() gives the undecoded values. msg.items() would decode all of them at
    # once, and a single exception would lose every header.
    for name, raw in msg.raw_items():
        try:
            header = msg.policy.header_fetch_parse(name, raw)
        except (HeaderParseError, ValueError, IndexError) as exc:
            # Rare, but the stdlib header parser has raised on hostile input before.
            unfolded = "".join(str(raw).splitlines())
            headers.append((name, unfolded))
            findings.append(
                Finding(
                    id="HEADER_UNPARSEABLE",
                    severity=Severity.MEDIUM,
                    description=f"The {name} header could not be parsed.",
                    evidence=f"{name}: {unfolded} ({type(exc).__name__})",
                )
            )
            continue
        headers.append((name, str(header)))
        for defect in header.defects:
            findings.append(
                Finding(
                    id="HEADER_DEFECT",
                    severity=Severity.LOW,
                    description=f"The {name} header is malformed.",
                    evidence=f"{name}: {header} ({defect})",
                )
            )
    return headers


def _record_defects(msg: EmailMessage, findings: list[Finding]) -> None:
    """Report structural damage anywhere in the MIME tree (broken boundaries and the like)."""
    for part in msg.walk():
        for defect in part.defects:
            findings.append(
                Finding(
                    id="PARSE_DEFECT",
                    severity=Severity.LOW,
                    description="The email's MIME structure is malformed.",
                    evidence=f"{part.get_content_type()}: {type(defect).__name__}",
                )
            )


def _read_text(part: EmailMessage, findings: list[Finding]) -> str:
    """Decode a text part. get_content() undoes base64/quoted-printable and the charset."""
    try:
        content = part.get_content()
    except LookupError:
        # The declared charset doesn't exist. Fall back to UTF-8, replacing bad bytes,
        # so the body is still available to the URL and content checks.
        charset = part.get_content_charset() or ""
        findings.append(
            Finding(
                id="UNKNOWN_CHARSET",
                severity=Severity.LOW,
                description="A body part declares a character set that doesn't exist.",
                evidence=charset,
            )
        )
        raw = part.get_payload(decode=True) or b""
        return raw.decode("utf-8", errors="replace")
    return content if isinstance(content, str) else ""


def _collect_attachments(
    msg: EmailMessage, body_parts: tuple[EmailMessage | None, ...]
) -> list[Attachment]:
    """Walk the MIME tree ourselves, so attachments nested at any depth are found.

    msg.iter_attachments() only looks at the top level and misses nested ones.
    msg.walk() can't stop at a forwarded email, so we use our own loop.
    """
    attachments: list[Attachment] = []
    stack: list[EmailMessage] = [msg]  # a loop, not recursion: hostile nesting can't blow the stack
    while stack:
        part = stack.pop()
        if part.get_content_type() == "message/rfc822":
            # A whole email attached inside this one: keep it as one opaque attachment.
            payload = part.get_payload()
            if isinstance(payload, list) and payload:
                data = payload[0].as_bytes()
            else:  # damaged forward: keep whatever raw text is there
                data = str(payload).encode("utf-8", errors="replace")
            attachments.append(
                Attachment(filename=part.get_filename(), content_type="message/rfc822", data=data)
            )
            continue
        if part.is_multipart():
            # reversed() so popping off the stack visits children in file order
            stack.extend(reversed(part.get_payload()))
            continue
        if any(part is body for body in body_parts):
            continue
        if part.get_content_disposition() == "attachment" or part.get_filename():
            attachments.append(
                Attachment(
                    filename=part.get_filename(),
                    content_type=part.get_content_type(),
                    data=part.get_payload(decode=True) or b"",
                )
            )
    return attachments
