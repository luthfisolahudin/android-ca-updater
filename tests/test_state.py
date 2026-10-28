from __future__ import annotations

import json
from pathlib import Path

import pytest

from android_ca_updater.config import Paths
from android_ca_updater.errors import ToolError
from android_ca_updater.state import STATE_VERSION, StateStore
from fakes import make_cert


def write_state(store: StateStore, payload: object) -> None:
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text(json.dumps(payload))


def test_load_returns_default_for_missing_file(state_store: StateStore) -> None:
    assert state_store.load() == {"version": STATE_VERSION, "devices": {}}


def test_load_tolerates_corrupt_json(state_store: StateStore) -> None:
    state_store.path.parent.mkdir(parents=True, exist_ok=True)
    state_store.path.write_text("{not json")
    assert state_store.load()["devices"] == {}


def test_load_rejects_a_newer_schema(state_store: StateStore) -> None:
    write_state(state_store, {"version": STATE_VERSION + 1, "devices": {}})
    with pytest.raises(ToolError, match="newer android-ca-updater"):
        state_store.load()


def test_track_records_name_sha1_and_version(state_store: StateStore) -> None:
    cert = make_cert(der=b"abc")
    state_store.track("S1", cert, "My Root")

    tracked = state_store.tracked("S1")
    assert tracked == {cert.fingerprint: {"name": "My Root", "sha1": cert.sha1}}

    payload = json.loads(state_store.path.read_text())
    assert payload["version"] == STATE_VERSION
    assert payload["devices"]["S1"]["installed"][cert.fingerprint]["sha1"] == cert.sha1


def test_untrack_removes_only_that_root(state_store: StateStore) -> None:
    first = make_cert(der=b"one", subject="CN=One")
    second = make_cert(der=b"two", subject="CN=Two")
    state_store.track("S1", first, "One")
    state_store.track("S1", second, "Two")

    state_store.untrack("S1", first.fingerprint)

    assert list(state_store.tracked("S1")) == [second.fingerprint]


def test_untrack_unknown_serial_is_a_noop(state_store: StateStore) -> None:
    state_store.untrack("missing", "f" * 64)
    assert not state_store.path.exists()


def test_legacy_string_form_is_migrated_on_read(state_store: StateStore) -> None:
    write_state(state_store, {"devices": {"S1": {"installed": {"f" * 64: "Old Root"}}}})
    assert state_store.tracked("S1") == {"f" * 64: {"name": "Old Root", "sha1": None}}


def test_tracked_skips_malformed_entries(state_store: StateStore) -> None:
    write_state(
        state_store,
        {"devices": {"S1": {"installed": {"a": 42, "b": {"name": 1, "sha1": "deadbeef"}}}}},
    )
    assert state_store.tracked("S1") == {"b": {"name": None, "sha1": "deadbeef"}}


def test_backfill_fills_missing_sha1(state_store: StateStore) -> None:
    cert = make_cert(der=b"abc")
    write_state(state_store, {"devices": {"S1": {"installed": {cert.fingerprint: "My Root"}}}})
    tracked = state_store.tracked("S1")

    state_store.backfill_sha1("S1", tracked, [cert])

    assert tracked[cert.fingerprint]["sha1"] == cert.sha1
    payload = json.loads(state_store.path.read_text())
    installed = payload["devices"]["S1"]["installed"]
    assert installed[cert.fingerprint]["sha1"] == cert.sha1


def test_backfill_without_missing_sha1_does_not_write(state_store: StateStore) -> None:
    cert = make_cert(der=b"abc")
    state_store.track("S1", cert, "My Root")
    before = state_store.path.read_text()

    state_store.backfill_sha1("S1", state_store.tracked("S1"), [])

    assert state_store.path.read_text() == before


def test_backfill_ignores_unknown_certificates(state_store: StateStore) -> None:
    cert = make_cert(der=b"abc")
    write_state(state_store, {"devices": {"S1": {"installed": {cert.fingerprint: "My Root"}}}})
    tracked = state_store.tracked("S1")

    state_store.backfill_sha1("S1", tracked, [])

    assert tracked[cert.fingerprint]["sha1"] is None


def test_state_path_is_created_on_first_write(state_store: StateStore) -> None:
    assert isinstance(state_store.path, Path)
    state_store.track("S1", make_cert(), "Root")
    assert state_store.path.exists()


def test_paths_from_env_uses_xdg(tmp_path: Path) -> None:
    env = {
        "HOME": str(tmp_path),
        "XDG_CACHE_HOME": str(tmp_path / "cache"),
        "XDG_STATE_HOME": str(tmp_path / "state"),
    }
    paths = Paths.from_env(env)
    assert paths.cache == tmp_path / "cache" / "android-ca-updater"
    assert paths.state == tmp_path / "state" / "android-ca-updater" / "state.json"


def test_paths_from_env_falls_back_to_home(tmp_path: Path) -> None:
    paths = Paths.from_env({"HOME": str(tmp_path)})
    assert paths.cache == tmp_path / ".cache" / "android-ca-updater"
    assert paths.cacert_pem == paths.cache / "cacert.pem"


def test_paths_from_env_ignores_empty_values(tmp_path: Path) -> None:
    paths = Paths.from_env({"HOME": str(tmp_path), "XDG_CACHE_HOME": "", "XDG_STATE_HOME": ""})
    assert paths.cache == tmp_path / ".cache" / "android-ca-updater"
