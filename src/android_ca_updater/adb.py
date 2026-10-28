"""adb discovery and device control."""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import Protocol

from .errors import NeedsUnlock, ToolError
from .process import run

_SDK_CANDIDATES = (
    Path.home() / "Android/Sdk/platform-tools/adb",
    Path("/usr/lib/android-sdk/platform-tools/adb"),
    Path("/opt/android-sdk/platform-tools/adb"),
)


class AdbDevice(Protocol):
    """The slice of device behavior the flows need (fakeable in tests)."""

    serial: str

    @property
    def model(self) -> str: ...

    @property
    def android_release(self) -> str: ...

    @property
    def sdk(self) -> int: ...

    @property
    def fingerprint(self) -> str: ...

    def shell(self, command: str, timeout: int = 90) -> str: ...

    def push(self, local: Path, remote: str) -> None: ...

    def pull(self, remote: str, local: Path) -> None: ...

    def getprop(self, name: str) -> str: ...

    def logcat_clear(self) -> None: ...

    def logcat(self) -> str: ...

    def is_locked(self) -> bool: ...

    def ensure_unlocked(self) -> None: ...


class Device:
    def __init__(self, adb: str, serial: str) -> None:
        self.adb = adb
        self.serial = serial

    def shell(self, command: str, timeout: int = 90) -> str:
        proc = run([self.adb, "-s", self.serial, "shell", command], timeout=timeout)
        return proc.stdout.decode("utf-8", "replace")

    def push(self, local: Path, remote: str) -> None:
        run([self.adb, "-s", self.serial, "push", str(local), remote])

    def pull(self, remote: str, local: Path) -> None:
        local.parent.mkdir(parents=True, exist_ok=True)
        run([self.adb, "-s", self.serial, "pull", remote, str(local)])

    def getprop(self, name: str) -> str:
        return self.shell(f"getprop {name}").strip()

    def logcat_clear(self) -> None:
        run([self.adb, "-s", self.serial, "logcat", "-c"], check=False)

    def logcat(self) -> str:
        proc = run([self.adb, "-s", self.serial, "logcat", "-d"], check=False, timeout=60)
        return proc.stdout.decode("utf-8", "replace")

    @property
    def model(self) -> str:
        return self.getprop("ro.product.model") or self.serial

    @property
    def android_release(self) -> str:
        return self.getprop("ro.build.version.release")

    @property
    def sdk(self) -> int:
        try:
            return int(self.getprop("ro.build.version.sdk"))
        except ValueError:
            return 0

    @property
    def fingerprint(self) -> str:
        return self.getprop("ro.build.fingerprint")

    def is_locked(self) -> bool:
        try:
            trust = self.shell("dumpsys trust")
        except ToolError:
            return False
        if re.search(r"deviceLocked=1", trust):
            return True
        return bool(re.search(r"mShowingLockscreen=true", self.shell("dumpsys window")))

    def ensure_unlocked(self) -> None:
        if self.is_locked():
            raise NeedsUnlock("device is locked - unlock the screen and try again")


def find_adb() -> str:
    override = os.environ.get("ADB")
    if override:
        return override
    found = shutil.which("adb")
    if found:
        return found
    for candidate in _SDK_CANDIDATES:
        if candidate.exists():
            return str(candidate)
    raise ToolError("adb not found: install Android platform-tools or set $ADB")


def pick_device(adb: str, serial: str | None) -> Device:
    proc = run([adb, "devices"])
    serials = [
        line.split("\t")[0]
        for line in proc.stdout.decode().splitlines()[1:]
        if line.strip().endswith("device") and "\t" in line
    ]
    if serial:
        if serial not in serials:
            raise ToolError(f"device {serial} not connected")
        return Device(adb, serial)
    if not serials:
        raise ToolError("no adb device found - connect the phone with USB debugging enabled")
    if len(serials) > 1:
        raise ToolError(f"multiple devices connected, pass --serial: {', '.join(serials)}")
    return Device(adb, serials[0])
