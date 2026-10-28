"""Drives Android's certificate installer to add a root as a user CA."""

from __future__ import annotations

import re
import shlex
import tempfile
import time
from pathlib import Path

from .adb import AdbDevice
from .certs import Cert
from .config import (
    CERT_INSTALLER_ACTIVITY,
    CERT_INSTALLER_PKG,
    DEVICE_DIR,
    OK_LABELS,
    SCREEN_LOCK_LABELS,
)
from .errors import NeedsScreenLock, ToolError
from .state import StateStore
from .uiautomator import (
    current_focus,
    find_node,
    ime_visible,
    node_bounds,
    screen_text,
    ui_dump,
    wait_for,
)


def safe_cert_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9 ._+-]", "", name)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned or "root-ca"


def install_root(
    device: AdbDevice,
    cert: Cert,
    name: str,
    state: StateStore,
    *,
    dry_run: bool = False,
) -> None:
    if cert.subject != cert.issuer:
        raise ToolError(f"refusing to install {cert.common_name}: not a self-signed root")
    if dry_run:
        return
    device.ensure_unlocked()
    slug = (
        re.sub(r"[^A-Za-z0-9._-]+", "-", safe_cert_name(name)).strip("-") or cert.fingerprint[:12]
    )
    remote = f"{DEVICE_DIR}/{slug}.crt"

    device.shell(f"mkdir -p {shlex.quote(DEVICE_DIR)}")
    with tempfile.TemporaryDirectory() as tmp:
        local = Path(tmp) / f"{slug}.crt"
        local.write_bytes(cert.der)
        device.push(local, remote)

    device.shell(
        f"am start -n {CERT_INSTALLER_ACTIVITY} -a android.intent.action.VIEW "
        f"-t application/x-x509-ca-cert -d {shlex.quote('file://' + remote)}"
    )
    if not wait_for(lambda: CERT_INSTALLER_PKG in current_focus(device), timeout=15):
        raise ToolError("certificate installer did not open")

    dump = ui_dump(device)
    if dump is None:
        raise ToolError("cannot read certificate installer UI")
    visible = screen_text(dump).lower()
    if any(label in visible for label in SCREEN_LOCK_LABELS):
        raise NeedsScreenLock(
            "Android requires a screen lock (PIN/pattern) before user CAs can be installed"
        )

    field = find_node(dump, class_name="EditText")
    if field is not None:
        center = node_bounds(field)
        if center is None:
            raise ToolError("cannot locate the certificate name field")
        device.shell(f"input tap {center[0]} {center[1]}")
        wait_for(lambda: ime_visible(device), timeout=6)
        typed_name = safe_cert_name(name)
        entry = None
        for _ in range(3):
            device.shell(f"input text {shlex.quote(typed_name.replace(' ', '%s'))}")
            time.sleep(0.5)
            dump = ui_dump(device)
            if dump is None:
                raise ToolError("certificate dialog closed while entering the name")
            entry = find_node(dump, class_name="EditText")
            if entry is not None and (entry.get("text") or "").strip():
                break
        if entry is None or not (entry.get("text") or "").strip():
            raise ToolError("could not type a certificate name into the installer")
        device.shell("input keyevent 4")
        time.sleep(0.8)
        if CERT_INSTALLER_PKG not in current_focus(device):
            raise ToolError("certificate dialog closed while entering the name")
        dump = ui_dump(device)
        if dump is None:
            raise ToolError("certificate dialog closed unexpectedly")

    button = find_node(dump, class_name="Button", labels=OK_LABELS)
    if button is None:
        raise ToolError("cannot find the confirm button in the certificate installer")
    center = node_bounds(button)
    if center:
        device.shell(f"input tap {center[0]} {center[1]}")

    if not wait_for(lambda: CERT_INSTALLER_PKG not in current_focus(device), timeout=25):
        suffix = ""
        leftover = screen_text(ui_dump(device))
        if leftover:
            suffix = f": {leftover[:160]}"
        raise ToolError(f"certificate installer did not finish{suffix}")
    state.track(device.serial, cert, safe_cert_name(name))
