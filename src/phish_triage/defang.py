"""Make domains, IPs and URLs unclickable in output (CLAUDE.md safety rule 5).

A report full of live links is a report someone will click. Defanged text still reads
fine to an analyst: hxxps://evil[.]com, 203.0.113[.]10, billing@example[.]com.

Minimal version for Phase 1 output. Phase 2 extends it for URL-specific cases.
"""

import re

# http:// or https:// at the start of a URL
_SCHEME = re.compile(r"\bhttp(s?)://", re.IGNORECASE)
# a dot with a letter, digit or hyphen on both sides: inside a domain, email or IPv4.
# A dot ending a sentence isn't touched, and "[.]" is never matched twice.
_INNER_DOT = re.compile(r"(?<=[A-Za-z0-9-])\.(?=[A-Za-z0-9-])")


def defang(text: str) -> str:
    """hxxp://, and [.] for dots inside names. IPv6 has no dots, so it's left as-is."""
    text = _SCHEME.sub(lambda match: f"hxxp{match.group(1).lower()}://", text)
    return _INNER_DOT.sub("[.]", text)
