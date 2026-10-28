"""Host probing and browser checks."""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from .adb import AdbDevice
from .certs import Cert
from .config import CHROME_ACTIVITY, CHROME_PACKAGE
from .errors import ToolError
from .tls import fetch_chain, resolve_anchor
from .truststore import StoreIndex

_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


@dataclass
class HostResult:
    host: str
    anchor: Cert | None
    source: str
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.source in {"system", "user"}


def analyse_host(
    host: str,
    bundle: list[Cert],
    store: StoreIndex | None,
    tracked: Mapping[str, object],
) -> HostResult:
    chain = fetch_chain(host)
    if not chain:
        return HostResult(host, None, "unreachable", "no TLS response")
    if store is not None and store.trusts_chain(chain):
        return HostResult(host, None, "system")
    anchor = resolve_anchor(chain, bundle)
    if anchor is None:
        return HostResult(host, None, "unknown", "cannot determine the anchor root")
    if anchor.not_after < datetime.now(UTC):
        return HostResult(host, anchor, "expired", "anchor root expired")
    if anchor.fingerprint in tracked:
        return HostResult(host, anchor, "user")
    return HostResult(host, anchor, "missing")


def browser_check(device: AdbDevice, host: str, wait: float = 4.0) -> tuple[bool | None, str]:
    try:
        listing = device.shell(f"pm list packages {CHROME_PACKAGE}")
    except ToolError:
        return None, "chrome not installed"
    if CHROME_PACKAGE not in listing:
        return None, "chrome not installed"
    device.logcat_clear()
    device.shell(
        f'am start -a android.intent.action.VIEW -d "https://{host}/?cau={int(time.time())}" '
        f"-n {CHROME_ACTIVITY}"
    )
    time.sleep(wait)
    codes = re.findall(r"net_error -(\d+)", device.logcat())
    if codes:
        return False, f"net_error -{codes[0]}"
    return True, ""


def validate_host(host: str) -> str:
    """Reject anything that is not a plain hostname or IPv4 literal."""
    candidate = host[:-1] if host.endswith(".") else host
    if not candidate or len(candidate) > 253:
        raise ToolError(f"invalid host: {host!r}")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        labels = candidate.split(".")
        if any(not _LABEL.match(label) for label in labels):
            raise ToolError(f"invalid host: {host!r}") from None
        if all(label.isdigit() for label in labels):
            raise ToolError(f"invalid host: {host!r}") from None
    else:
        if address.version == 6:
            raise ToolError("IPv6 hosts are not supported")
    return candidate


def _extract_host(value: str) -> str:
    text = value.strip()
    if "://" in text:
        try:
            parts = urlsplit(text)
        except ValueError as exc:
            raise ToolError(f"invalid host entry: {value!r}") from exc
        if parts.scheme not in {"http", "https"}:
            raise ToolError(f"unsupported URL scheme in host entry: {value!r}")
        return parts.hostname or ""
    if text.startswith("[") or text.count(":") > 1:
        raise ToolError("IPv6 hosts are not supported")
    return text.split("/", 1)[0].split(":", 1)[0]


def parse_hosts(values: Sequence[str]) -> list[str]:
    hosts: list[str] = []
    for value in values:
        entries = _read_host_file(value) or value.split(",")
        for entry in entries:
            candidate = entry.strip()
            if not candidate or candidate.startswith("#"):
                continue
            host = validate_host(_extract_host(candidate))
            if host not in hosts:
                hosts.append(host)
    return hosts


def _read_host_file(value: str) -> list[str] | None:
    try:
        path = Path(value)
        if not path.is_file():
            return None
        return path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
