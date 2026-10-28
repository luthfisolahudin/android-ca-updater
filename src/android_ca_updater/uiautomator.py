"""uiautomator dump parsing and tap helpers."""

from __future__ import annotations

import re
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable

from .adb import AdbDevice
from .config import UI_DUMP_PATH
from .errors import ToolError

_BOUNDS = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


def ui_dump(device: AdbDevice) -> ET.Element | None:
    device.shell(f"rm -f {UI_DUMP_PATH}", timeout=30)
    try:
        device.shell(f"uiautomator dump {UI_DUMP_PATH}", timeout=120)
        payload = device.shell(f"cat {UI_DUMP_PATH}", timeout=60)
    except ToolError:
        return None
    if "hierarchy" not in payload:
        return None
    try:
        return ET.fromstring(payload)
    except ET.ParseError:
        return None


def ime_visible(device: AdbDevice) -> bool:
    try:
        return "mInputShown=true" in device.shell("dumpsys input_method", timeout=30)
    except ToolError:
        return False


def node_bounds(node: ET.Element) -> tuple[int, int] | None:
    match = _BOUNDS.match(node.get("bounds", ""))
    if not match:
        return None
    left, top, right, bottom = (int(value) for value in match.groups())
    return (left + right) // 2, (top + bottom) // 2


def find_node(
    root: ET.Element | None,
    *,
    class_name: str | None = None,
    labels: tuple[str, ...] | None = None,
) -> ET.Element | None:
    if root is None:
        return None
    for node in root.iter("node"):
        if class_name and not node.get("class", "").endswith(class_name):
            continue
        if labels is not None:
            text = (node.get("text") or "").strip().lower()
            if text not in labels:
                continue
        return node
    return None


def find_node_by_text(root: ET.Element | None, needles: tuple[str, ...]) -> ET.Element | None:
    if root is None:
        return None
    for node in root.iter("node"):
        text = (node.get("text") or "").strip().lower()
        if text and any(needle in text for needle in needles):
            return node
    return None


def find_node_exact(root: ET.Element | None, labels: tuple[str, ...]) -> ET.Element | None:
    return find_node(root, labels=labels)


def screen_text(root: ET.Element | None) -> str:
    if root is None:
        return ""
    return " ".join((node.get("text") or "") for node in root.iter("node")).strip()


def current_focus(device: AdbDevice) -> str:
    return device.shell("dumpsys window | grep -E 'mCurrentFocus'")


def wait_for(predicate: Callable[[], bool], timeout: float, interval: float = 0.5) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def tap_node(device: AdbDevice, node: ET.Element | None, what: str) -> None:
    if node is None:
        raise ToolError(f"cannot find {what} on screen")
    center = node_bounds(node)
    if center is None:
        raise ToolError(f"cannot locate {what} bounds")
    device.shell(f"input tap {center[0]} {center[1]}")
