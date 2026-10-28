from __future__ import annotations

import pytest

from android_ca_updater.config import CREDENTIAL_ACTIVITIES
from android_ca_updater.credentials import (
    open_credential_manager,
    reconcile,
    remove_user_ca,
    select_user_tab,
    user_ca_names,
)
from android_ca_updater.errors import NeedsUnlock, ToolError
from android_ca_updater.state import StateStore
from fakes import FakeDevice, make_cert

ACTIVITY_1, ACTIVITY_2 = CREDENTIAL_ACTIVITIES
NAME = "My Root"

TAB = (
    '<hierarchy><node class="android.widget.TextView" text="User" '
    'bounds="[0,0][100,100]"/></hierarchy>'
)
LIST_WITH = (
    f'<hierarchy><node class="android.widget.TextView" text="{NAME}" '
    'bounds="[0,0][100,100]"/></hierarchy>'
)
LIST_WITHOUT = (
    '<hierarchy><node class="android.widget.TextView" text="Other" '
    'bounds="[0,0][100,100]"/></hierarchy>'
)
REMOVE_DIALOG = (
    '<hierarchy><node class="android.widget.Button" text="Remove" '
    'bounds="[0,0][100,100]"/></hierarchy>'
)
CONFIRM_DIALOG = (
    '<hierarchy><node class="android.widget.Button" text="OK" bounds="[0,0][100,100]"/></hierarchy>'
)
ENTRY = (
    '<hierarchy><node class="android.widget.TextView" text="Certificates" '
    'bounds="[0,0][100,100]"/></hierarchy>'
)


def test_open_credential_manager_uses_the_first_activity() -> None:
    device = FakeDevice()
    open_credential_manager(device)
    starts = [command for command in device.commands if command.startswith("am start -S")]
    assert len(starts) == 1
    assert ACTIVITY_1 in starts[0]


def test_open_credential_manager_falls_back_to_the_second_activity() -> None:
    device = FakeDevice()
    device.start_responses[ACTIVITY_1] = "Error: Activity class does not exist."
    open_credential_manager(device)
    starts = [command for command in device.commands if command.startswith("am start -S")]
    assert len(starts) == 2
    assert ACTIVITY_1 in starts[0]
    assert ACTIVITY_2 in starts[1]


def test_open_credential_manager_falls_back_to_security_settings(
    no_sleep: None,
) -> None:
    device = FakeDevice(dumps=[ENTRY])
    device.start_responses[ACTIVITY_1] = "Error: Activity class does not exist."
    device.start_responses[ACTIVITY_2] = "Error: Activity class does not exist."

    open_credential_manager(device)

    assert any("android.settings.SECURITY_SETTINGS" in command for command in device.commands)
    assert device.taps


def test_open_credential_manager_reports_missing_screen(no_sleep: None) -> None:
    device = FakeDevice()
    device.start_responses[ACTIVITY_1] = "Error: Activity class does not exist."
    device.start_responses[ACTIVITY_2] = "Error: Activity class does not exist."
    with pytest.raises(ToolError, match="does not expose a trusted-credentials screen"):
        open_credential_manager(device)


def test_select_user_tab_taps_the_tab() -> None:
    device = FakeDevice(dumps=[TAB])
    select_user_tab(device)
    assert device.taps == ["input tap 50 50"]


def test_user_ca_names_returns_visible_labels() -> None:
    device = FakeDevice(dumps=[TAB, LIST_WITH])
    assert user_ca_names(device) == {NAME}


def test_user_ca_names_is_none_when_locked() -> None:
    device = FakeDevice(locked=True)
    assert user_ca_names(device) is None
    assert device.commands == []


def test_user_ca_names_is_none_without_a_dump() -> None:
    device = FakeDevice(dumps=["not a dump"])
    assert user_ca_names(device) is None


def test_remove_user_ca_happy_path(no_sleep: None) -> None:
    device = FakeDevice(dumps=[TAB, LIST_WITH, REMOVE_DIALOG, CONFIRM_DIALOG, LIST_WITHOUT])
    remove_user_ca(device, NAME)
    assert len(device.taps) == 4


def test_remove_user_ca_detects_a_still_listed_certificate(no_sleep: None) -> None:
    device = FakeDevice(dumps=[TAB, LIST_WITH, REMOVE_DIALOG, CONFIRM_DIALOG, LIST_WITH])
    with pytest.raises(ToolError, match="still listed after removal"):
        remove_user_ca(device, NAME)


def test_remove_user_ca_requires_a_listed_certificate(no_sleep: None) -> None:
    device = FakeDevice(dumps=[TAB, LIST_WITHOUT])
    with pytest.raises(ToolError, match="is not listed"):
        remove_user_ca(device, NAME)


def test_remove_user_ca_requires_an_unlocked_device() -> None:
    device = FakeDevice(locked=True)
    with pytest.raises(NeedsUnlock):
        remove_user_ca(device, NAME)


def test_reconcile_untracks_vanished_roots(state_store: StateStore) -> None:
    kept = make_cert(der=b"kept", subject="CN=Kept Root")
    vanished = make_cert(der=b"gone", subject="CN=Gone Root")
    state_store.track("FAKE123", kept, "Kept Root")
    state_store.track("FAKE123", vanished, "Gone Root")
    kept_list = (
        '<hierarchy><node class="android.widget.TextView" text="Kept Root" '
        'bounds="[0,0][100,100]"/></hierarchy>'
    )
    device = FakeDevice(dumps=[TAB, kept_list])

    reconcile(device, state_store)

    assert list(state_store.tracked("FAKE123")) == [kept.fingerprint]


def test_reconcile_is_a_noop_when_the_list_is_unavailable(
    state_store: StateStore,
) -> None:
    cert = make_cert(der=b"kept", subject="CN=Kept Root")
    state_store.track("FAKE123", cert, "Kept Root")

    reconcile(FakeDevice(locked=True), state_store)

    assert list(state_store.tracked("FAKE123")) == [cert.fingerprint]
