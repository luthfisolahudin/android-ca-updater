from __future__ import annotations

import pytest

from android_ca_updater import installer
from android_ca_updater.config import CERT_INSTALLER_PKG, DEVICE_DIR
from android_ca_updater.errors import NeedsScreenLock, ToolError
from android_ca_updater.installer import install_root, safe_cert_name
from android_ca_updater.state import StateStore
from fakes import FakeDevice, make_cert

DIALOG = (
    '<hierarchy><node class="android.widget.LinearLayout" bounds="[0,0][540,960]">'
    '<node class="android.widget.EditText" text="" bounds="[48,405][492,458]"/>'
    '<node class="android.widget.Button" text="Oke" bounds="[48,655][273,712]"/>'
    "</node></hierarchy>"
)
FILLED = DIALOG.replace('text=""', 'text="My Root"')
NO_BUTTON = (
    '<hierarchy><node class="android.widget.EditText" text="My Root" '
    'bounds="[48,405][492,458]"/></hierarchy>'
)
CONFIRM = (
    '<hierarchy><node class="android.widget.Button" text="Oke" '
    'bounds="[48,655][273,712]"/></hierarchy>'
)
LOCKED_UI = (
    '<hierarchy><node class="android.widget.TextView" text="Kunci layar diperlukan" '
    'bounds="[0,0][100,100]"/></hierarchy>'
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('ISRG Root X1 "test"; rm -rf /', "ISRG Root X1 test rm -rf"),
        ("a;b", "ab"),
        ('a"b', "ab"),
        ("a$b", "ab"),
        ("***", "root-ca"),
        ("  spaced   name  ", "spaced name"),
        ("Cert+Name_1.0", "Cert+Name_1.0"),
    ],
)
def test_safe_cert_name(raw: str, expected: str) -> None:
    assert safe_cert_name(raw) == expected


def test_dry_run_sends_no_commands(state_store: StateStore) -> None:
    device = FakeDevice()
    install_root(device, make_cert(), "My Root", state_store, dry_run=True)
    assert device.commands == []
    assert device.pushes == []


def test_refuses_non_self_signed_certificates(state_store: StateStore) -> None:
    device = FakeDevice()
    cert = make_cert(subject="CN=Leaf", issuer="CN=Root")
    with pytest.raises(ToolError, match="not a self-signed root"):
        install_root(device, cert, "Leaf", state_store)


def test_install_happy_path(state_store: StateStore, no_sleep: None) -> None:
    device = FakeDevice(dumps=[DIALOG, FILLED, CONFIRM])
    cert = make_cert(der=b"cert-bytes", subject="CN=My Root")

    install_root(device, cert, "My Root", state_store)

    assert any(command.startswith("mkdir -p") for command in device.commands)
    assert len(device.pushes) == 1
    _, remote = device.pushes[0]
    assert remote.startswith(DEVICE_DIR)
    assert device.pushed_bytes[remote] == b"cert-bytes"
    assert device.taps[0].startswith("input tap")
    assert "input text My%sRoot" in device.commands
    assert any("file://" in command for command in device.commands)
    assert state_store.tracked("FAKE123")[cert.fingerprint]["name"] == "My Root"


def test_installer_that_never_opens_fails(
    state_store: StateStore, no_sleep: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    device = FakeDevice(dumps=[DIALOG], installer_starts=False)
    monkeypatch.setattr(installer, "wait_for", lambda predicate, timeout, interval=0.5: predicate())
    with pytest.raises(ToolError, match="installer did not open"):
        install_root(device, make_cert(), "My Root", state_store)


def test_screen_lock_requirement_is_reported(state_store: StateStore, no_sleep: None) -> None:
    device = FakeDevice(dumps=[LOCKED_UI])
    with pytest.raises(NeedsScreenLock, match="screen lock"):
        install_root(device, make_cert(), "My Root", state_store)


def test_missing_confirm_button_fails(state_store: StateStore, no_sleep: None) -> None:
    device = FakeDevice(dumps=[DIALOG, FILLED, NO_BUTTON])
    with pytest.raises(ToolError, match="confirm button"):
        install_root(device, make_cert(), "My Root", state_store)


def test_name_that_never_sticks_fails(state_store: StateStore, no_sleep: None) -> None:
    device = FakeDevice(dumps=[DIALOG])
    with pytest.raises(ToolError, match="could not type a certificate name"):
        install_root(device, make_cert(), "My Root", state_store)


def test_dialog_closing_while_typing_fails(state_store: StateStore, no_sleep: None) -> None:
    device = FakeDevice(dumps=[DIALOG, "<hierarchy>"])
    with pytest.raises(ToolError, match="closed while entering the name"):
        install_root(device, make_cert(), "My Root", state_store)


def test_installer_that_never_closes_fails(
    state_store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    device = FakeDevice(dumps=[DIALOG, FILLED, CONFIRM, DIALOG])
    device.close_installer_on_tap = False
    monkeypatch.setattr(installer, "wait_for", lambda predicate, timeout, interval=0.5: predicate())
    with pytest.raises(ToolError, match="installer did not finish"):
        install_root(device, make_cert(), "My Root", state_store)


def test_install_requires_an_unlocked_device(state_store: StateStore) -> None:
    device = FakeDevice(locked=True)
    with pytest.raises(ToolError, match="device is locked"):
        install_root(device, make_cert(), "My Root", state_store)


def test_installer_activity_is_used(state_store: StateStore, no_sleep: None) -> None:
    device = FakeDevice(dumps=[DIALOG, FILLED, CONFIRM])
    install_root(device, make_cert(), "My Root", state_store)
    assert any(CERT_INSTALLER_PKG in command for command in device.commands)
