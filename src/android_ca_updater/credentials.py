"""Android's trusted-credentials screens: inspect and remove user CAs."""

from __future__ import annotations

import shlex
import time

from .adb import AdbDevice
from .config import (
    CREDENTIAL_ACTIVITIES,
    CREDENTIAL_LABELS,
    OK_LABELS,
    REMOVE_LABELS,
    SECURITY_SETTINGS_ACTION,
    USER_TAB_LABELS,
)
from .errors import ToolError
from .state import StateStore
from .uiautomator import (
    current_focus,
    find_node,
    find_node_by_text,
    find_node_exact,
    tap_node,
    ui_dump,
    wait_for,
)


def open_credential_manager(device: AdbDevice) -> None:
    for activity in CREDENTIAL_ACTIVITIES:
        started = device.shell(f"am start -S -n {shlex.quote(activity)}")
        if "does not exist" in started or "Error" in started:
            continue
        if wait_for(lambda: "com.android.settings" in current_focus(device), timeout=10):
            return
    device.shell(f"am start -a {SECURITY_SETTINGS_ACTION}")
    if not wait_for(lambda: "settings" in current_focus(device), timeout=10):
        raise ToolError("cannot open Android security settings")
    entry = find_node_by_text(ui_dump(device), CREDENTIAL_LABELS)
    if entry is None:
        raise ToolError(
            "this ROM does not expose a trusted-credentials screen; remove the CA manually "
            "from Settings > Security > Trusted credentials"
        )
    tap_node(device, entry, "the trusted credentials entry")
    time.sleep(1.2)


def select_user_tab(device: AdbDevice) -> None:
    tab = find_node_exact(ui_dump(device), USER_TAB_LABELS)
    if tab is not None:
        tap_node(device, tab, "the user certificate tab")
        time.sleep(1.0)


def user_ca_names(device: AdbDevice) -> set[str] | None:
    """Names currently listed under the user tab, or None if unavailable."""
    if device.is_locked():
        return None
    try:
        open_credential_manager(device)
        select_user_tab(device)
        dump = ui_dump(device)
    except ToolError:
        return None
    if dump is None:
        return None
    return {(node.get("text") or "").strip() for node in dump.iter("node")}


def reconcile(device: AdbDevice, state: StateStore) -> None:
    names = user_ca_names(device)
    if names is None:
        return
    for fingerprint, info in state.tracked(device.serial).items():
        name = info.get("name")
        if name and name not in names:
            state.untrack(device.serial, fingerprint)


def remove_user_ca(device: AdbDevice, name: str) -> None:
    device.ensure_unlocked()
    open_credential_manager(device)
    select_user_tab(device)

    target = find_node_by_text(ui_dump(device), (name.lower(),))
    if target is None:
        raise ToolError(f"certificate {name!r} is not listed")
    tap_node(device, target, f"certificate {name!r}")
    time.sleep(1.0)

    confirm = find_node(ui_dump(device), class_name="Button", labels=REMOVE_LABELS)
    if confirm is None:
        raise ToolError("cannot find the remove action for this certificate")
    tap_node(device, confirm, "the remove button")
    time.sleep(1.0)

    final = find_node(ui_dump(device), class_name="Button", labels=OK_LABELS)
    if final is not None:
        tap_node(device, final, "the confirmation button")
        time.sleep(1.0)

    if find_node_by_text(ui_dump(device), (name.lower(),)) is not None:
        raise ToolError(f"certificate {name!r} is still listed after removal")
