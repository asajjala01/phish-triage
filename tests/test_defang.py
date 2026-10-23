import pytest

from phish_triage.defang import defang


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example[.]com"),
        ("mail.example.co.uk", "mail[.]example[.]co[.]uk"),
        ("billing@example.com", "billing@example[.]com"),
        ("203.0.113.10", "203[.]0[.]113[.]10"),
        ("http://evil.example/login", "hxxp://evil[.]example/login"),
        ("HTTPS://evil.example", "hxxps://evil[.]example"),
        ("2001:db8::25", "2001:db8::25"),  # IPv6: no dots, left alone
        ("End of a sentence.", "End of a sentence."),  # trailing dot isn't inside a name
        ("no domains here", "no domains here"),
        ("", ""),
    ],
)
def test_defang(raw: str, expected: str) -> None:
    assert defang(raw) == expected


def test_defanging_twice_changes_nothing() -> None:
    once = defang("see https://evil.example from 203.0.113.10")
    assert defang(once) == once
