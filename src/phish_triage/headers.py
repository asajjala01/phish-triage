"""Sender checks: who the email claims to be from vs where replies and bounces really go.

From and Reply-To are written by the sender and can say anything. Return-Path is added
by the receiving server from the SMTP envelope (MAIL FROM), and it's the domain SPF
checks. Domains are compared by organization (mail.example.com == example.com), using
the Public Suffix List so that example.co.uk isn't mistaken for the organization "co.uk".
"""

import ipaddress
from email import policy
from email.errors import HeaderParseError
from email.headerregistry import Address
from email.utils import parseaddr

from publicsuffixlist import PublicSuffixList

from phish_triage.models import Finding, ParsedEmail, Severity

# Loads the list bundled inside the package. No network access, ever.
_PSL = PublicSuffixList()


def org_domain(domain: str) -> str:
    """The registrable domain an organization owns: mail.example.co.uk -> example.co.uk."""
    domain = domain.strip().lower().rstrip(".")
    if _is_ip_literal(domain):
        return domain  # user@[192.0.2.1]: the PSL would turn this into "2.1]"
    # None for a bare suffix ("com") or a single label ("localhost"): use it as-is.
    return _PSL.privatesuffix(domain) or domain


def check_sender(parsed: ParsedEmail) -> list[Finding]:
    """Compare From against Reply-To and Return-Path."""
    findings: list[Finding] = []
    from_headers = parsed.get_headers("From")
    from_addresses = _addresses(parsed, "From")

    # Mail clients disagree on which of several From headers to show, so duplicates
    # let an attacker show the victim one sender while filters check another.
    if len(from_headers) > 1 or len(from_addresses) > 1:
        findings.append(
            Finding(
                id="SENDER_MULTIPLE_FROM",
                severity=Severity.HIGH,
                description="The email has more than one From sender.",
                evidence=" | ".join(from_headers),
            )
        )

    usable = [address for address in from_addresses if address.domain]
    if not usable:
        findings.append(
            Finding(
                id="SENDER_FROM_MISSING",
                severity=Severity.MEDIUM,
                description="No usable From address; the sender can't be identified.",
                evidence=from_headers[0] if from_headers else "",
            )
        )
        return findings  # nothing to compare the other headers against

    sender = usable[0]  # with duplicates, compare against the first (topmost)
    sender_org = org_domain(sender.domain)

    mismatched = [
        address
        for address in _addresses(parsed, "Reply-To")
        if address.domain and org_domain(address.domain) != sender_org
    ]
    if mismatched:
        findings.append(
            Finding(
                id="SENDER_REPLY_TO_MISMATCH",
                severity=Severity.MEDIUM,
                description="Replies go to a different organization than the sender's.",
                evidence=f"From: {sender.addr_spec} -> Reply-To: "
                + ", ".join(address.addr_spec for address in mismatched),
            )
        )

    return_path = _return_path(parsed)
    if return_path and org_domain(return_path.rpartition("@")[2]) != sender_org:
        findings.append(
            Finding(
                id="SENDER_RETURN_PATH_MISMATCH",
                # Weak alone: mailing services (SendGrid, SES) use their own bounce domains.
                severity=Severity.LOW,
                description="Bounces go to a different organization than the sender's.",
                evidence=f"From: {sender.addr_spec} -> Return-Path: {return_path}",
            )
        )

    return findings


def _addresses(parsed: ParsedEmail, name: str) -> list[Address]:
    """Every address in every copy of an address header (From, Reply-To)."""
    found: list[Address] = []
    for value in parsed.get_headers(name):
        try:
            header = policy.default.header_factory(name, value)
        except (HeaderParseError, ValueError, IndexError):
            continue  # the parser already recorded this header as unparseable
        found.extend(header.addresses)
    return found


def _return_path(parsed: ParsedEmail) -> str | None:
    """The topmost Return-Path address, or None for a bounce (<>) or junk.

    The stdlib doesn't treat Return-Path as an address header, so parseaddr does the work.
    """
    values = parsed.get_headers("Return-Path")
    if not values:
        return None
    _, address = parseaddr(values[0])
    return address if "@" in address else None


def _is_ip_literal(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain.strip("[]").removeprefix("ipv6:"))
    except ValueError:
        return False
    return True
