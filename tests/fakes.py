"""Fake device, HTTP and provider implementations used by the tests."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from android_ca_updater.bundle import BUNDLE_MAX_AGE, Bundle
from android_ca_updater.certdata import CertRecord
from android_ca_updater.certs import Cert
from android_ca_updater.cli import Context
from android_ca_updater.config import CERT_INSTALLER_PKG, Paths
from android_ca_updater.console import Terminal
from android_ca_updater.errors import NeedsUnlock, ToolError
from android_ca_updater.state import StateStore

EMPTY_HIERARCHY = "<hierarchy></hierarchy>"
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def make_cert(
    der: bytes = b"der",
    *,
    subject: str = "CN=Test Root",
    issuer: str | None = None,
    not_after: datetime | None = None,
) -> Cert:
    return Cert(
        der=der,
        subject=subject,
        issuer=issuer if issuer is not None else subject,
        not_after=not_after or datetime(2100, 1, 1, tzinfo=UTC),
    )


class FakeDevice:
    def __init__(
        self,
        *,
        serial: str = "FAKE123",
        model: str = "Fake Phone",
        android_release: str = "6.0.1",
        sdk: int = 23,
        fingerprint: str = "fake/build/fingerprint",
        dumps: Sequence[str] | None = None,
        locked: bool = False,
        chrome: bool = True,
        logcat: str = "",
        root_installer: bool = False,
        props: dict[str, str] | None = None,
        installer_starts: bool = True,
    ) -> None:
        self.serial = serial
        self._model = model
        self._release = android_release
        self._sdk = sdk
        self._fingerprint = fingerprint
        self.props = props or {}
        self.dumps = list(dumps) if dumps else [EMPTY_HIERARCHY]
        self.locked = locked
        self.chrome = chrome
        self.logcat_output = logcat
        self.installer_open = root_installer
        self.installer_starts = installer_starts
        self.start_responses: dict[str, str] = {}

        self.commands: list[str] = []
        self.taps: list[str] = []
        self.pushes: list[tuple[Path, str]] = []
        self.pulls: list[tuple[str, Path]] = []
        self.pushed_bytes: dict[str, bytes] = {}
        self.logcat_cleared = False
        self.close_installer_on_tap = True
        self._dump_index = 0
        self._advance_dump = False

    @property
    def model(self) -> str:
        return self._model

    @property
    def android_release(self) -> str:
        return self._release

    @property
    def sdk(self) -> int:
        return self._sdk

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    def getprop(self, name: str) -> str:
        return self.props.get(name, "")

    def shell(self, command: str, timeout: int = 90) -> str:
        self.commands.append(command)

        if command.startswith("getprop "):
            return self.getprop(command.split(" ", 1)[1])
        if command.startswith("dumpsys window"):
            focus = (
                "com.android.certinstaller/.CertInstallerMain"
                if self.installer_open
                else "com.android.settings/.Settings"
            )
            return f"  mCurrentFocus=Window{{1 u0 {focus}}}"
        if command.startswith("dumpsys input_method"):
            return "mInputShown=true"
        if command.startswith("dumpsys trust"):
            return "deviceLocked=1" if self.locked else "deviceLocked=0"
        if "uiautomator dump" in command:
            self._advance_dump = True
            return "UI hierarchy dumped to: /sdcard/android-ca-updater-ui.xml"
        if command.startswith("cat "):
            return self._next_dump()
        if command.startswith("pm list packages"):
            return "package:com.android.chrome" if self.chrome else ""
        if command.startswith("am start"):
            for marker, response in self.start_responses.items():
                if marker in command:
                    return response
            if CERT_INSTALLER_PKG in command and self.installer_starts:
                self.installer_open = True
            return ""
        if command.startswith("input tap"):
            self.taps.append(command)
            if self.installer_open and self.close_installer_on_tap and len(self.taps) >= 2:
                self.installer_open = False
            return ""
        if command.startswith("input "):
            self.taps.append(command)
            return ""
        if command.startswith("mkdir "):
            return ""
        return ""

    def _next_dump(self) -> str:
        xml = self.dumps[min(self._dump_index, len(self.dumps) - 1)]
        if self._advance_dump:
            self._dump_index += 1
            self._advance_dump = False
        return xml

    def push(self, local: Path, remote: str) -> None:
        self.pushes.append((local, remote))
        self.pushed_bytes[remote] = local.read_bytes()

    def pull(self, remote: str, local: Path) -> None:
        self.pulls.append((remote, local))
        raise ToolError(f"cannot pull {remote}")

    def logcat_clear(self) -> None:
        self.logcat_cleared = True

    def logcat(self) -> str:
        return self.logcat_output

    def is_locked(self) -> bool:
        return self.locked

    def ensure_unlocked(self) -> None:
        if self.locked:
            raise NeedsUnlock("device is locked - unlock the screen and try again")


class FakeHttp:
    def __init__(self, responses: dict[str, tuple[bytes | None, dict[str, str]]] | None = None):
        self.responses = responses or {}
        self.calls: list[tuple[str, str | None, str | None]] = []

    def get(
        self, url: str, etag: str | None, last_modified: str | None
    ) -> tuple[bytes | None, dict[str, str]]:
        self.calls.append((url, etag, last_modified))
        if url not in self.responses:
            raise OSError(f"no route to {url}")
        return self.responses[url]


class FakeBundles:
    def __init__(
        self, certs: Sequence[Cert], *, origin: str = "test", fetched_at: datetime | None = NOW
    ):
        self.bundle = Bundle(
            certs=list(certs),
            origin=origin,
            fetched_at=fetched_at,
            sha256="ab" * 32,
        )
        self.calls: list[dict[str, object]] = []

    def get(
        self,
        *,
        refresh: bool = False,
        quiet: bool = False,
        max_age: timedelta = BUNDLE_MAX_AGE,
        local_path: Path | None = None,
    ) -> Bundle:
        self.calls.append(
            {
                "refresh": refresh,
                "quiet": quiet,
                "max_age": max_age,
                "local_path": local_path,
            }
        )
        return self.bundle


class FakeCertdata:
    def __init__(self, records: dict[str, CertRecord] | None = None):
        self.records = records or {}
        self.calls: list[dict[str, object]] = []

    def get(
        self,
        *,
        refresh: bool = False,
        quiet: bool = False,
        max_age: timedelta = BUNDLE_MAX_AGE,
    ) -> dict[str, CertRecord]:
        self.calls.append({"refresh": refresh, "quiet": quiet, "max_age": max_age})
        return self.records


def make_context(
    *,
    paths: Paths,
    device: FakeDevice,
    bundles: FakeBundles | None = None,
    certdata: FakeCertdata | None = None,
    state: StateStore | None = None,
    now: datetime = NOW,
) -> Context:
    return Context(
        paths=paths,
        terminal=Terminal(enabled=False),
        state=state or StateStore(paths.state),
        bundles=bundles or FakeBundles([make_cert()]),
        certdata=certdata or FakeCertdata(),
        device_factory=lambda serial: device,
        now=lambda: now,
    )
