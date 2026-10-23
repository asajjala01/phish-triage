"""Data structures shared by every stage: parsing, checks, scoring and reports."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """How much a finding should worry an analyst. Scoring weights live in config, not here."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Finding:
    """One observation about an email. Every check returns these instead of printing."""

    id: str  # stable machine name, e.g. "PARSE_DEFECT"; scoring.yaml keys off this
    severity: Severity
    description: str  # one human-readable sentence
    evidence: str = ""  # the exact value that triggered it (defanged at output time)


@dataclass(frozen=True)
class Attachment:
    """An attachment held in memory only. Never written to disk (CLAUDE.md safety rule 2)."""

    filename: str | None  # as claimed by the sender; may be missing or a lie
    content_type: str  # as claimed by the sender; Phase 3 checks it against magic bytes
    data: bytes = field(repr=False)  # transfer-decoded bytes; repr=False keeps them out of logs

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass(frozen=True)
class AuthResult:
    """One method's verdict from an Authentication-Results header, e.g. spf=pass."""

    method: str  # "spf", "dkim", "dmarc" (lowercased); unknown methods are kept too
    result: str  # "pass", "fail", "softfail", "none", ... (lowercased)
    # ("smtp.mailfrom", "example.com"), ("header.d", "example.com"), ("reason", "...")
    properties: tuple[tuple[str, str], ...] = ()

    def __str__(self) -> str:
        pairs = " ".join(f"{key}={value}" for key, value in self.properties)
        return f"{self.method}={self.result} {pairs}".strip()


@dataclass(frozen=True)
class AuthenticationResults:
    """A parsed Authentication-Results header (RFC 8601)."""

    authserv_id: str  # the server that vouches for these results; "" if the header omits it
    results: tuple[AuthResult, ...]


@dataclass(frozen=True)
class Brand:
    """A brand phishers impersonate, and the domains it really sends from (config/brands.yaml)."""

    name: str
    domains: tuple[str, ...]
    aliases: tuple[str, ...] = ()  # other names for it, e.g. "Office 365" for Microsoft


@dataclass
class ParsedEmail:
    """Everything later checks need from one .eml file."""

    # (name, value) in file order. A list, not a dict: headers repeat (Received) and
    # order matters (only the topmost Authentication-Results can be trusted).
    headers: list[tuple[str, str]] = field(default_factory=list)
    subject: str | None = None
    text_body: str | None = None
    html_body: str | None = None
    attachments: list[Attachment] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)  # problems hit while parsing

    def get_headers(self, name: str) -> list[str]:
        """All values of a header, top to bottom. Header names are case-insensitive."""
        wanted = name.lower()
        return [value for key, value in self.headers if key.lower() == wanted]
