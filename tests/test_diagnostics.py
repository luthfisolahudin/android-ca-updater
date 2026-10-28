from __future__ import annotations

from datetime import UTC, datetime

import pytest

from android_ca_updater import diagnostics
from android_ca_updater.certs import Cert
from android_ca_updater.diagnostics import HostResult, analyse_host, browser_check
from android_ca_updater.truststore import StoreIndex
from fakes import FakeDevice, make_cert


def test_host_result_ok_only_for_trusted_sources() -> None:
    assert HostResult("h", None, "system").ok
    assert HostResult("h", None, "user").ok
    assert not HostResult("h", None, "missing").ok
    assert not HostResult("h", None, "unreachable").ok


def test_analyse_host_without_a_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(diagnostics, "fetch_chain", lambda host: [])
    result = analyse_host("example.com", [], None, {})
    assert result.source == "unreachable"
    assert result.error == "no TLS response"


def test_analyse_host_trusted_by_the_system_store(monkeypatch: pytest.MonkeyPatch) -> None:
    cert = make_cert()
    monkeypatch.setattr(diagnostics, "fetch_chain", lambda host: [cert])

    class TrustingStore:
        def trusts_chain(self, chain: list[Cert]) -> bool:
            return True

    result = analyse_host("example.com", [], TrustingStore(), {})
    assert result.source == "system"


def test_analyse_host_unknown_anchor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(diagnostics, "fetch_chain", lambda host: [make_cert()])
    monkeypatch.setattr(diagnostics, "resolve_anchor", lambda chain, bundle: None)
    result = analyse_host("example.com", [], None, {})
    assert result.source == "unknown"


def test_analyse_host_expired_anchor(monkeypatch: pytest.MonkeyPatch) -> None:
    anchor = make_cert(not_after=datetime(2001, 1, 1, tzinfo=UTC))
    monkeypatch.setattr(diagnostics, "fetch_chain", lambda host: [anchor])
    monkeypatch.setattr(diagnostics, "resolve_anchor", lambda chain, bundle: anchor)
    result = analyse_host("example.com", [], None, {})
    assert result.source == "expired"


def test_analyse_host_tracked_anchor(monkeypatch: pytest.MonkeyPatch) -> None:
    anchor = make_cert()
    monkeypatch.setattr(diagnostics, "fetch_chain", lambda host: [anchor])
    monkeypatch.setattr(diagnostics, "resolve_anchor", lambda chain, bundle: anchor)
    result = analyse_host("example.com", [], None, {anchor.fingerprint: {"name": "Root"}})
    assert result.source == "user"


def test_analyse_host_missing_anchor(monkeypatch: pytest.MonkeyPatch) -> None:
    anchor = make_cert()
    monkeypatch.setattr(diagnostics, "fetch_chain", lambda host: [anchor])
    monkeypatch.setattr(diagnostics, "resolve_anchor", lambda chain, bundle: anchor)
    result = analyse_host("example.com", [], None, {})
    assert result.source == "missing"


def test_analyse_host_ignores_stores_that_do_not_trust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    anchor = make_cert()
    monkeypatch.setattr(diagnostics, "fetch_chain", lambda host: [anchor])
    monkeypatch.setattr(diagnostics, "resolve_anchor", lambda chain, bundle: anchor)
    store = StoreIndex(by_fingerprint={}, by_subject={})
    assert analyse_host("example.com", [], store, {}).source == "missing"


def test_browser_check_without_chrome(no_sleep: None) -> None:
    device = FakeDevice(chrome=False)
    assert browser_check(device, "example.com") == (None, "chrome not installed")


def test_browser_check_detects_tls_errors(no_sleep: None) -> None:
    device = FakeDevice(logcat="I/chromium: net_error -202 cert error")
    assert browser_check(device, "example.com") == (False, "net_error -202")


def test_browser_check_passes_without_errors(no_sleep: None) -> None:
    device = FakeDevice(logcat="I/chromium: loaded")
    assert browser_check(device, "example.com") == (True, "")
    assert device.logcat_cleared is True
