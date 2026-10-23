from pathlib import Path

import pytest

from phish_triage.config import ConfigError, load_brands

SHIPPED = Path(__file__).parent.parent / "config" / "brands.yaml"


def test_shipped_brand_list_loads() -> None:
    brands = load_brands(SHIPPED)
    assert {"PayPal", "Microsoft"} <= {brand.name for brand in brands}
    assert all(brand.domains for brand in brands)


def test_aliases_are_optional() -> None:
    paypal = next(brand for brand in load_brands(SHIPPED) if brand.name == "PayPal")
    assert paypal.aliases == ()


@pytest.mark.parametrize(
    ("content", "complaint"),
    [
        ("", "top-level 'brands' list"),
        ("brands: PayPal\n", "top-level 'brands' list"),
        ("brands:\n  - PayPal\n", "expected a mapping"),
        ("brands:\n  - domains: [paypal.com]\n", "'name'"),
        ("brands:\n  - name: PayPal\n", "'domains'"),
        ("brands:\n  - name: PayPal\n    domains: []\n", "'domains'"),
        ("brands:\n  - name: PayPal\n    domains: paypal.com\n", "'domains'"),
        ("brands:\n  - name: X\n    domains: [x.com]\n    aliases: X Corp\n", "'aliases'"),
    ],
)
def test_bad_brand_file_fails_loudly(tmp_path: Path, content: str, complaint: str) -> None:
    path = tmp_path / "brands.yaml"
    path.write_text(content)
    with pytest.raises(ConfigError, match=complaint):
        load_brands(path)


def test_invalid_yaml_is_a_config_error(tmp_path: Path) -> None:
    path = tmp_path / "brands.yaml"
    path.write_text("brands: [unclosed\n")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_brands(path)


def test_yaml_python_tags_are_refused(tmp_path: Path) -> None:
    # safe_load refuses tags that would build Python objects. yaml.load would run this.
    path = tmp_path / "brands.yaml"
    path.write_text("brands: !!python/object/apply:os.system ['echo pwned']\n")
    with pytest.raises(ConfigError, match="python/object"):
        load_brands(path)
