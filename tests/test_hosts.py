from __future__ import annotations

from pathlib import Path

import pytest

from android_ca_updater.diagnostics import parse_hosts, validate_host
from android_ca_updater.errors import ToolError


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://github.com/foo/bar", "github.com"),
        ("pypi.org:443", "pypi.org"),
        ("http://example.com:8080/path", "example.com"),
        ("example.com.", "example.com"),
        ("192.0.2.10", "192.0.2.10"),
        ("sub.domain.example.co.uk", "sub.domain.example.co.uk"),
    ],
)
def test_accepts_urls_ports_and_paths(value: str, expected: str) -> None:
    assert parse_hosts([value]) == [expected]


def test_accepts_comma_lists() -> None:
    assert parse_hosts(["a.test,b.test"]) == ["a.test", "b.test"]


def test_accepts_a_file_with_comments(tmp_path: Path) -> None:
    path = tmp_path / "hosts.txt"
    path.write_text("# comment\n\ngithub.com\nhttps://f-droid.org/\n")
    assert parse_hosts([str(path)]) == ["github.com", "f-droid.org"]


def test_deduplicates() -> None:
    assert parse_hosts(["a.test,a.test", "https://a.test/"]) == ["a.test"]


def test_comments_only_returns_empty() -> None:
    assert parse_hosts(["# nothing"]) == []


@pytest.mark.parametrize(
    "value",
    [
        "exa mple.com",
        "bad-.com",
        "-bad.com",
        "a..b",
        "foo;bar",
        "$(whoami)",
        "a" * 64 + ".com",
        "ftp://example.com",
        "::1",
        "999.1.1.1",
    ],
)
def test_rejects_invalid_hosts(value: str) -> None:
    with pytest.raises(ToolError):
        parse_hosts([value])


def test_validate_host_strips_the_root_label() -> None:
    assert validate_host("example.com.") == "example.com"


def test_validate_host_rejects_overlong_names() -> None:
    with pytest.raises(ToolError, match="invalid host"):
        validate_host(".".join(["a" * 63] * 4))
