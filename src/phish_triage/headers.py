"""Header checks: who the email claims to be from, and what the receiving server verified.

Sender checks. From and Reply-To are written by the sender and can say anything.
Return-Path is added by the receiving server from the SMTP envelope (MAIL FROM), and
it's the domain SPF checks. Domains are compared by organization (mail.example.com ==
example.com), using the Public Suffix List so that example.co.uk isn't mistaken for the
organization "co.uk".

Auth checks. Only the topmost Authentication-Results header is read. Each server adds
its headers above the existing ones, so the topmost was added by the receiving server.
Everything below came from earlier in the path, which an attacker can write.

Received chain. Each server adds a Received header on top, so reading bottom-up gives
the path. Only the hops our own servers added are real; the origin is where an outside
server handed the email in, since our server saw that connection's IP itself.
"""

import ipaddress
import re
from collections.abc import Sequence
from datetime import datetime
from email import policy
from email.errors import HeaderParseError
from email.headerregistry import Address
from email.utils import parseaddr, parsedate_to_datetime

from publicsuffixlist import PublicSuffixList

from phish_triage.models import (
    AuthenticationResults,
    AuthResult,
    Brand,
    Finding,
    Hop,
    ParsedEmail,
    ReceivedChain,
    Severity,
)

# Loads the list bundled inside the package. No network access, ever.
_PSL = PublicSuffixList()

# An email address written inside a display name: "security@paypal.com" <x@example.net>
_ADDRESS_IN_TEXT = re.compile(r"[\w.+-]+@((?:[\w-]+\.)+[\w-]+)")


def org_domain(domain: str) -> str:
    """The registrable domain an organization owns: mail.example.co.uk -> example.co.uk."""
    domain = domain.strip().lower().rstrip(".")
    if _is_ip_literal(domain):
        return domain  # user@[192.0.2.1]: the PSL would turn this into "2.1]"
    # None for a bare suffix ("com") or a single label ("localhost"): use it as-is.
    return _PSL.privatesuffix(domain) or domain


def check_sender(parsed: ParsedEmail, brands: Sequence[Brand]) -> list[Finding]:
    """Compare From against Reply-To and Return-Path, and its display name against its domain."""
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

    findings.extend(_check_display_name(sender, sender_org, brands))
    return findings


def _check_display_name(sender: Address, sender_org: str, brands: Sequence[Brand]) -> list[Finding]:
    """Most mail clients show only the display name, so attackers put a trusted name there."""
    findings: list[Finding] = []
    name = sender.display_name
    shown = f'"{name}" <{sender.addr_spec}>'

    foreign = [
        match.group(0)
        for match in _ADDRESS_IN_TEXT.finditer(name)
        if org_domain(match.group(1)) != sender_org
    ]
    if foreign:
        findings.append(
            Finding(
                id="SENDER_DISPLAY_NAME_ADDRESS",
                severity=Severity.HIGH,
                description="The display name shows an email address from a different domain.",
                evidence=shown,
            )
        )

    for brand in brands:
        if not _names_brand(name, brand):
            continue
        if sender_org in {org_domain(domain) for domain in brand.domains}:
            continue  # the brand really sent it
        findings.append(
            Finding(
                id="SENDER_DISPLAY_NAME_BRAND",
                severity=Severity.HIGH,
                description=f"The display name claims to be {brand.name}, "
                f"but the address isn't one of {brand.name}'s domains.",
                evidence=shown,
            )
        )
    return findings


def _names_brand(display_name: str, brand: Brand) -> bool:
    """Whole-word, case-insensitive: "Apple ID" matches Apple, "Applebee's" doesn't."""
    for term in (brand.name, *brand.aliases):
        # (?<!\w) and (?!\w) instead of \b, so names ending in a symbol still work.
        if re.search(rf"(?<!\w){re.escape(term)}(?!\w)", display_name, re.IGNORECASE):
            return True
    return False


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


# --- auth checks: SPF / DKIM / DMARC from Authentication-Results ---

_ERRORS = {"temperror", "permerror"}

# (method, result) -> (finding id, severity, description). DKIM is handled separately.
_AUTH_RULES = {
    ("spf", "fail"): (
        "AUTH_SPF_FAIL",
        Severity.MEDIUM,
        "SPF failed: the sending server isn't allowed to send for the envelope domain.",
    ),
    ("spf", "softfail"): (
        "AUTH_SPF_SOFTFAIL",
        Severity.LOW,
        "SPF soft-failed: the envelope domain says this server probably isn't allowed.",
    ),
    ("dmarc", "fail"): (
        "AUTH_DMARC_FAIL",
        Severity.HIGH,
        "DMARC failed: nothing authenticated the domain shown in From.",
    ),
    ("dmarc", "none"): (
        "AUTH_DMARC_NONE",
        Severity.LOW,
        "The From domain publishes no DMARC policy, so it can be spoofed freely.",
    ),
}


def check_auth(parsed: ParsedEmail) -> list[Finding]:
    """Report SPF, DKIM and DMARC problems from the topmost Authentication-Results."""
    values = parsed.get_headers("Authentication-Results")
    if not values:
        return [
            Finding(
                id="AUTH_RESULTS_MISSING",
                severity=Severity.MEDIUM,
                description="No Authentication-Results header; SPF/DKIM/DMARC can't be verified.",
            )
        ]
    top = parse_authentication_results(values[0])
    if top is None:
        return [
            Finding(
                id="AUTH_RESULTS_UNPARSEABLE",
                severity=Severity.LOW,
                description="The topmost Authentication-Results header couldn't be parsed.",
                evidence=values[0],
            )
        ]

    server = top.authserv_id or "unknown server"
    findings: list[Finding] = []
    for result in top.results:
        evidence = f"{server}: {result}"  # who vouched, and what they said
        if result.method == "dkim":
            continue  # judged across all signatures below
        rule = _AUTH_RULES.get((result.method, result.result))
        if rule is not None:
            finding_id, severity, description = rule
            findings.append(Finding(finding_id, severity, description, evidence))
        elif result.method in {"spf", "dmarc"} and result.result in _ERRORS:
            findings.append(_auth_error(result, evidence))

    # Mail often carries several DKIM signatures, and a mailing service's can break
    # while the sender's own still verifies. One passing signature is enough.
    dkim = [result for result in top.results if result.method == "dkim"]
    if dkim and not any(result.result == "pass" for result in dkim):
        failed = [result for result in dkim if result.result == "fail"]
        errored = [result for result in dkim if result.result in _ERRORS]
        if failed:
            findings.append(
                Finding(
                    id="AUTH_DKIM_FAIL",
                    severity=Severity.MEDIUM,
                    description="DKIM failed: the signature doesn't verify, so the message "
                    "was altered or the signer is forged.",
                    evidence="; ".join(f"{server}: {result}" for result in failed),
                )
            )
        elif errored:
            findings.append(_auth_error(errored[0], f"{server}: {errored[0]}"))
    return findings


def _auth_error(result: AuthResult, evidence: str) -> Finding:
    return Finding(
        id=f"AUTH_{result.method.upper()}_ERROR",
        severity=Severity.LOW,
        description=f"{result.method.upper()} couldn't be evaluated ({result.result}).",
        evidence=evidence,
    )


def parse_authentication_results(value: str) -> AuthenticationResults | None:
    """Parse one Authentication-Results header value; None if it's malformed.

    Format (RFC 8601):  authserv-id; method=result ptype.property=value ...; method=...
    Comments in (parentheses) and "quoted strings" may contain ; and = themselves,
    which is why this can't just be value.split(";").
    """
    text = _strip_comments(value)
    if text is None:
        return None
    # The RFC allows whitespace around "=" ("spf = pass"). Squash it so tokens hold together.
    text = re.sub(r"\s*=\s*", "=", text)
    segments = _split_unquoted(text, ";")
    head = _split_unquoted(segments[0], None)  # "mx.example.org" or "mx.example.org 1"
    if not head:
        return None
    if "=" in head[0]:
        # No authserv-id: the header starts straight with "spf=...". The RFC requires one,
        # but Microsoft 365 leaves it out, so treat every segment as a result.
        authserv_id = ""
        rest = [segment for segment in segments if segment.strip()]
    else:
        authserv_id = head[0]
        rest = [segment for segment in segments[1:] if segment.strip()]
    if [segment.strip().lower() for segment in rest] == ["none"]:
        return AuthenticationResults(authserv_id, ())  # server checked nothing

    results: list[AuthResult] = []
    for segment in rest:
        tokens = _split_unquoted(segment, None)
        method, sep, result = tokens[0].partition("=")
        if not sep or not method or not result:
            return None
        properties = tuple(
            (key.lower(), val.strip('"'))
            for key, _, val in (token.partition("=") for token in tokens[1:])
        )
        results.append(
            AuthResult(
                method=method.split("/")[0].lower(),  # "dkim/1" -> "dkim" (version suffix)
                result=result.lower(),
                properties=properties,
            )
        )
    if not results:
        return None
    return AuthenticationResults(authserv_id, tuple(results))


def _strip_comments(value: str) -> str | None:
    """Replace (comments) with a space. They nest, and can hold ; = and quotes.

    None if the parentheses or quotes are unbalanced.
    """
    out: list[str] = []
    depth = 0
    in_quotes = False
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\" and (in_quotes or depth):
            if in_quotes:
                out.append(value[i : i + 2])  # keep escaped characters inside quotes
            i += 2  # inside a comment, an escaped ( or ) must not change the depth
            continue
        if depth:
            depth += {"(": 1, ")": -1}.get(char, 0)
        elif in_quotes:
            out.append(char)
            in_quotes = char != '"'
        elif char == "(":
            depth = 1
            out.append(" ")
        elif char == '"':
            in_quotes = True
            out.append(char)
        else:
            out.append(char)
        i += 1
    if depth or in_quotes:
        return None
    return "".join(out)


def _split_unquoted(text: str, separator: str | None) -> list[str]:
    """Split on a separator (or on whitespace if None), ignoring any inside "quotes"."""
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    for char in text:
        if char == '"':
            in_quotes = not in_quotes
        is_separator = char.isspace() if separator is None else char == separator
        if is_separator and not in_quotes:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    parts = [part.strip() for part in parts]
    return [part for part in parts if part] if separator is None else parts


# --- Received chain: the path the email took, and where it came in from outside ---

# Ranges that never belong to an outside sender. An explicit list instead of ipaddress's
# is_private / is_global: those count the documentation ranges (192.0.2.0/24 and friends)
# as private, and carrier-grade NAT (100.64.0.0/10) as not private.
_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",  # RFC 1918 private
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",  # loopback
        "::1/128",
        "169.254.0.0/16",  # link-local
        "fe80::/10",
        "100.64.0.0/10",  # carrier-grade NAT
        "fc00::/7",  # IPv6 unique local
    )
)

# Clause keywords. The lookbehind stops "envelope-from" or "mail.from.example" matching.
_RECEIVED_KEYWORD = re.compile(r"(?<![\w.-])(from|by|via|with|id|for)\s", re.IGNORECASE)
_BRACKETED_IP = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]", re.IGNORECASE)
_RDNS_BEFORE_IP = re.compile(r"([\w.-]+)\s+\[(?:IPv6:)?[0-9A-Fa-f:.]+\]", re.IGNORECASE)


def analyze_received(parsed: ParsedEmail) -> ReceivedChain:
    """Every hop in travel order, plus the hop where an outside server handed the email in."""
    top_first = [parse_received(value) for value in parsed.get_headers("Received")]
    # Walk down from our side; the first external handoff is the origin. Everything below
    # it was written by the sender's side and can be invented.
    origin = next((hop for hop in top_first if _is_external_handoff(hop)), None)
    return ReceivedChain(hops=tuple(reversed(top_first)), origin=origin)


def check_received(parsed: ParsedEmail) -> list[Finding]:
    chain = analyze_received(parsed)
    if not chain.hops:
        return [
            Finding(
                id="RECEIVED_MISSING",
                severity=Severity.LOW,
                description="No Received headers; the email's path can't be traced.",
            )
        ]
    if chain.origin is None:
        return [
            Finding(
                id="RECEIVED_ORIGIN_UNKNOWN",
                severity=Severity.LOW,
                description="No hop shows an outside server handing this email in.",
                evidence=f"{len(chain.hops)} hops, all internal or unreadable",
            )
        ]
    return [
        Finding(
            id="RECEIVED_ORIGIN",
            severity=Severity.INFO,
            description="The IP that handed this email to the receiving organization.",
            evidence=hop_source(chain.origin),
        )
    ]


def hop_source(hop: Hop) -> str:
    """'203.0.113.10 (out.example.com) -> mx.example.org', saying when a name is unverified."""
    if hop.from_ip is None:
        source = "(no connection info)"
    elif hop.rdns_verified:
        source = f"{hop.from_ip} ({hop.from_rdns})"
    else:
        claimed = hop.from_rdns or hop.from_helo
        source = f"{hop.from_ip} ({f'unverified name {claimed}' if claimed else 'no name'})"
    return f"{source} -> {hop.by_host or 'unknown server'}"


def parse_received(value: str) -> Hop:
    """Parse one Received header. Formats vary by mail server, so every field is optional.

    from helo (rdns [ip]) by host with protocol id x for <rcpt>; date
    """
    clauses, separator, date_text = value.rpartition(";")
    if not separator:
        clauses, date_text = value, ""
    sections = _received_sections(clauses)
    from_text = sections.get("from", "")
    rdns = _rdns(from_text)
    return Hop(
        raw=value,
        from_helo=_first_word(from_text),
        from_rdns=rdns,
        rdns_verified=rdns is not None and "may be forged" not in from_text.lower(),
        from_ip=_connection_ip(from_text),
        by_host=_first_word(sections.get("by", "")),
        protocol=_first_word(sections.get("with", "")),
        timestamp=_parse_date(date_text),
    )


def _is_external_handoff(hop: Hop) -> bool:
    if hop.from_ip is None:
        return False  # nothing to attribute: local delivery, webmail, or unreadable
    ip = ipaddress.ip_address(hop.from_ip)
    if any(ip in network for network in _INTERNAL_NETWORKS):
        return False
    # Same organization on both ends means relaying inside one org. Only a verified
    # reverse-DNS name counts, never the HELO, which the sender types. Even rDNS isn't
    # proof: whoever owns an IP sets its PTR record, so an attacker can point their own
    # IP at our domain. Receiving servers that check the name resolves back to the same
    # IP mark a failure as "may be forged" or "unknown", and we fall back to the IP alone.
    # Limitation: a server that skips that check, or doesn't mark a failure, leaves a
    # forged PTR looking verified here, and this code can't tell the difference.
    if hop.rdns_verified and hop.from_rdns and hop.by_host:
        return org_domain(hop.from_rdns) != org_domain(hop.by_host)
    return True


def _received_sections(text: str) -> dict[str, str]:
    """Split into from / by / with / ... sections. Keywords inside (comments) don't count."""
    outside, _ = _split_comments(text)
    matches = list(_RECEIVED_KEYWORD.finditer(outside))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        # each section runs until the next keyword, or to the end of the text
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections.setdefault(match.group(1).lower(), text[match.end() : end].strip())
    return sections


def _connection_ip(from_text: str) -> str | None:
    """The IP the receiving server saw, not one the sender claimed.

    Servers record the real connection inside the comment: "helo (rdns [ip])". A
    bracketed IP before it is usually the HELO the sender typed ("from [1.2.3.4] ..."),
    except in Exim, which writes the real IP there. So outside is the last resort.
    """
    outside, inside = _split_comments(from_text)
    for match in _BRACKETED_IP.finditer(inside):
        if ip := _valid_ip(match.group(1)):
            return ip
    for token in re.split(r"[\s()\[\],=]+", inside):  # Exchange: "host (2603:10b6::1)"
        if ip := _valid_ip(token):
            return ip
    for match in _BRACKETED_IP.finditer(outside):
        if ip := _valid_ip(match.group(1)):
            return ip
    return None


def _rdns(from_text: str) -> str | None:
    """The reverse-DNS name right before the IP in the comment. None if 'unknown' or absent."""
    _, inside = _split_comments(from_text)
    match = _RDNS_BEFORE_IP.search(inside)
    if match is None:
        return None
    name = match.group(1).rstrip(".").lower()  # Gmail writes "mail.example.com."
    return None if name in {"", "unknown"} else name


def _split_comments(text: str) -> tuple[str, str]:
    """Two same-length copies of text: (comments) blanked out, and only the comments kept."""
    outside: list[str] = []
    inside: list[str] = []
    depth = 0
    for char in text:
        if char == "(":
            depth += 1
        outside.append(" " if depth else char)
        inside.append(char if depth else " ")
        if char == ")" and depth:
            depth -= 1
    return "".join(outside), "".join(inside)


def _first_word(section: str) -> str | None:
    outside, _ = _split_comments(section)
    words = outside.split()
    return words[0] if words else None


def _valid_ip(text: str) -> str | None:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _parse_date(text: str) -> datetime | None:
    try:
        return parsedate_to_datetime(text.strip())
    except (TypeError, ValueError):
        return None
