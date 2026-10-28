from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from android_ca_updater.config import OK_LABELS
from android_ca_updater.errors import ToolError
from android_ca_updater.uiautomator import (
    find_node,
    find_node_by_text,
    find_node_exact,
    ime_visible,
    node_bounds,
    screen_text,
    tap_node,
    ui_dump,
    wait_for,
)
from fakes import FakeDevice

XML = (
    '<hierarchy><node class="android.widget.LinearLayout" bounds="[0,0][540,960]">'
    '<node class="android.widget.EditText" text="" bounds="[48,405][492,458]"/>'
    '<node class="android.widget.Button" text="Oke" bounds="[48,655][273,712]"/>'
    '<node class="android.widget.Button" text="Batal" bounds="[273,655][492,712]"/>'
    "</node></hierarchy>"
)


@pytest.fixture
def root() -> ET.Element:
    return ET.fromstring(XML)


def test_finds_edit_text_center(root: ET.Element) -> None:
    node = find_node(root, class_name="EditText")
    assert node is not None
    assert node_bounds(node) == (270, 431)


def test_finds_ok_button_by_label(root: ET.Element) -> None:
    node = find_node(root, class_name="Button", labels=OK_LABELS)
    assert node is not None
    assert node.get("text") == "Oke"
    assert node_bounds(node) == (160, 683)


def test_unknown_label_returns_none(root: ET.Element) -> None:
    assert find_node(root, class_name="Button", labels=("nope",)) is None


def test_none_root_returns_none() -> None:
    assert find_node(None, class_name="Button") is None


def test_malformed_bounds_return_none() -> None:
    node = ET.fromstring('<node class="android.widget.Button" bounds="oops"/>')
    assert node_bounds(node) is None


def test_find_node_by_text_matches_substrings(root: ET.Element) -> None:
    node = find_node_by_text(root, ("ok",))
    assert node is not None
    assert node.get("text") == "Oke"


def test_find_node_exact_requires_the_whole_label(root: ET.Element) -> None:
    assert find_node_exact(root, ("oke",)) is not None
    assert find_node_exact(root, ("ok",)) is None


def test_screen_text_joins_visible_labels(root: ET.Element) -> None:
    assert screen_text(root) == "Oke Batal"


def test_tap_node_sends_the_center(root: ET.Element) -> None:
    device = FakeDevice()
    tap_node(device, find_node(root, class_name="Button", labels=OK_LABELS), "the OK button")
    assert device.taps == ["input tap 160 683"]


def test_tap_node_missing_node_raises() -> None:
    with pytest.raises(ToolError, match="cannot find"):
        tap_node(FakeDevice(), None, "the OK button")


def test_ui_dump_parses_valid_xml() -> None:
    device = FakeDevice(dumps=[XML])
    dump = ui_dump(device)
    assert dump is not None
    assert dump.tag == "hierarchy"


def test_ui_dump_returns_none_for_garbage() -> None:
    assert ui_dump(FakeDevice(dumps=["not a dump"])) is None


def test_ui_dump_returns_none_for_broken_xml() -> None:
    assert ui_dump(FakeDevice(dumps=["<hierarchy><node"])) is None


def test_ime_visible_reads_dumpsys() -> None:
    assert ime_visible(FakeDevice())


def test_wait_for_returns_immediately() -> None:
    assert wait_for(lambda: True, timeout=1)


def test_wait_for_times_out() -> None:
    assert not wait_for(lambda: False, timeout=0)
