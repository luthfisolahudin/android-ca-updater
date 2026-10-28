"""Subprocess and filesystem primitives."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import ToolError

OPENSSL_HINT = "install openssl (libssl) and make sure it is in PATH"


def run(
    cmd: Sequence[str],
    *,
    data: bytes | None = None,
    timeout: int = 120,
    check: bool = True,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run a command, mapping process failures to `ToolError`."""
    try:
        proc = subprocess.run(cmd, input=data, capture_output=True, timeout=timeout, env=env)
    except FileNotFoundError as exc:
        raise ToolError(f"command not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"timed out: {' '.join(cmd[:4])}") from exc
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or b"").decode("utf-8", "replace").strip()
        detail = detail.splitlines()[0] if detail else ""
        raise ToolError(f"{' '.join(cmd[:3])}: {detail[:400]}")
    return proc


def write_atomic(path: Path, data: str | bytes) -> None:
    """Write `data` to `path` via a synced temporary file and atomic replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = data.encode("utf-8") if isinstance(data, str) else data
    fd, tmp_name = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def read_json(path: Path) -> dict[str, Any] | None:
    """Read a JSON object, returning `None` for missing or malformed files."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def require_command(name: str, hint: str) -> str:
    """Return the resolved path of `name`, or raise a helpful `ToolError`."""
    found = shutil.which(name)
    if found is None:
        raise ToolError(f"{name} not found: {hint}")
    return found


def require_openssl() -> str:
    return require_command("openssl", OPENSSL_HINT)
