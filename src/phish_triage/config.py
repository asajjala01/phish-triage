"""Load YAML config files into typed objects, failing loudly on a bad file."""

from pathlib import Path

import yaml

from phish_triage.models import Brand


class ConfigError(ValueError):
    """A config file is missing a field or has the wrong shape."""


def load_brands(path: Path) -> list[Brand]:
    # safe_load, never yaml.load: plain yaml.load can build arbitrary Python objects
    # from tags in the file, which turns a config file into code execution.
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: not valid YAML ({exc})") from exc
    if not isinstance(data, dict) or not isinstance(data.get("brands"), list):
        raise ConfigError(f"{path}: expected a top-level 'brands' list")

    brands: list[Brand] = []
    for index, entry in enumerate(data["brands"]):
        where = f"{path}: brands[{index}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where}: expected a mapping")
        name = entry.get("name")
        domains = entry.get("domains")
        aliases = entry.get("aliases", [])
        if not isinstance(name, str) or not name.strip():
            raise ConfigError(f"{where}: 'name' must be a non-empty string")
        if not _is_string_list(domains) or not domains:
            raise ConfigError(f"{where}: 'domains' must be a non-empty list of strings")
        if not _is_string_list(aliases):
            raise ConfigError(f"{where}: 'aliases' must be a list of strings")
        brands.append(Brand(name=name, domains=tuple(domains), aliases=tuple(aliases)))
    return brands


def _is_string_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)
