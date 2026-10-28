"""Terminal styling and shared renderers."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

from .adb import AdbDevice
from .truststore import StoreIndex


@dataclass
class Terminal:
    """ANSI styling; `enabled=None` resolves tty/NO_COLOR once at construction."""

    enabled: bool | None = field(default=None)

    def __post_init__(self) -> None:
        if self.enabled is None:
            self.enabled = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    def wrap(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def ok(self, text: str) -> str:
        return self.wrap(text, "32")

    def bad(self, text: str) -> str:
        return self.wrap(text, "31")

    def warn(self, text: str) -> str:
        return self.wrap(text, "33")

    def dim(self, text: str) -> str:
        return self.wrap(text, "2")

    def error(self, message: str) -> None:
        print(self.bad(f"error: {message}"), file=sys.stderr)


def print_device(
    terminal: Terminal,
    device: AdbDevice,
    store: StoreIndex | None,
    tracked_count: int,
) -> None:
    print(f"device      {device.model} | Android {device.android_release} (API {device.sdk})")
    if store is not None:
        print(f"system CAs  {len(store)} roots")
    else:
        print(
            "system CAs  "
            + terminal.warn("unavailable (could not read /system/etc/security/cacerts)")
        )
    print(f"user CAs    {tracked_count} roots installed by this tool")
    if device.sdk >= 24:
        print(
            terminal.dim(
                "note        apps targeting API 24+ ignore user CAs; "
                "browsers and older apps still benefit"
            )
        )
