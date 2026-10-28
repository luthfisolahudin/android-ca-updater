from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from android_ca_updater import process
from android_ca_updater.errors import ToolError
from conftest import requires_openssl


def test_run_returns_output() -> None:
    result = process.run([sys.executable, "-c", "print('hi')"])
    assert result.stdout == b"hi\n"


def test_run_missing_command() -> None:
    with pytest.raises(ToolError, match="command not found"):
        process.run(["definitely-not-a-real-command"])


def test_run_nonzero_exit_raises() -> None:
    with pytest.raises(ToolError, match="false"):
        process.run(["false"])


def test_run_check_false_returns_the_result() -> None:
    assert process.run(["false"], check=False).returncode == 1


def test_run_timeout() -> None:
    with pytest.raises(ToolError, match="timed out"):
        process.run([sys.executable, "-c", "import time; time.sleep(2)"], timeout=1)


def test_write_atomic_creates_parents_and_reads_back(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "file.txt"
    process.write_atomic(target, "hello")
    assert target.read_text() == "hello"
    assert sorted(path.name for path in target.parent.iterdir()) == ["file.txt"]


def test_write_atomic_accepts_bytes(tmp_path: Path) -> None:
    target = tmp_path / "blob.bin"
    process.write_atomic(target, b"\x00\x01")
    assert target.read_bytes() == b"\x00\x01"


def test_write_atomic_removes_the_temp_file_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "file.txt"

    def boom(fd: int) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(process.os, "fsync", boom)
    with pytest.raises(OSError, match="disk full"):
        process.write_atomic(target, "data")
    assert list(tmp_path.iterdir()) == []


def test_read_json(tmp_path: Path) -> None:
    assert process.read_json(tmp_path / "missing.json") is None
    (tmp_path / "bad.json").write_text("{oops")
    assert process.read_json(tmp_path / "bad.json") is None
    (tmp_path / "list.json").write_text("[]")
    assert process.read_json(tmp_path / "list.json") is None
    (tmp_path / "ok.json").write_text('{"a": 1}')
    assert process.read_json(tmp_path / "ok.json") == {"a": 1}


def test_parse_timestamp() -> None:
    assert process.parse_timestamp(None) is None
    assert process.parse_timestamp("not a date") is None
    assert process.parse_timestamp(123) is None
    assert process.parse_timestamp("2026-01-01T00:00:00+00:00") == datetime(2026, 1, 1, tzinfo=UTC)


def test_require_command_finds_python() -> None:
    assert process.require_command("python3", "hint")


def test_require_command_reports_the_hint() -> None:
    with pytest.raises(ToolError, match="install openssl"):
        process.require_command("nope-not-here", "install openssl")


@requires_openssl
def test_require_openssl() -> None:
    assert process.require_openssl()
