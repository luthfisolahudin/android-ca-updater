from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta

import pytest

from android_ca_updater import bundle as bundle_module
from android_ca_updater.bundle import (
    CA_SOURCES,
    Bundle,
    BundleStore,
    assert_trusted_url,
    prune_parsed_cache,
    split_bundle,
    validate_bundle,
)
from android_ca_updater.config import Paths
from android_ca_updater.errors import ToolError
from conftest import FIXTURES, requires_openssl
from fakes import NOW, FakeHttp, make_cert

pytestmark = requires_openssl

ROOT_A_TEXT = (FIXTURES / "root-a.pem").read_text()
ROOT_B_TEXT = (FIXTURES / "root-b.pem").read_text()
TWO_ROOTS = ROOT_A_TEXT + ROOT_B_TEXT


def test_split_bundle_parses_every_block() -> None:
    certs = split_bundle(TWO_ROOTS)
    assert [cert.common_name for cert in certs] == ["Test Root Alpha", "Test Root Beta"]


def test_split_bundle_writes_parsed_cache(paths: Paths) -> None:
    split_bundle(TWO_ROOTS, paths.cache)
    assert len(list(paths.cache.glob("parsed-*.json"))) == 1


def test_split_bundle_reuses_parsed_cache(paths: Paths, monkeypatch: pytest.MonkeyPatch) -> None:
    split_bundle(TWO_ROOTS, paths.cache)
    monkeypatch.setattr(bundle_module, "parse_cert", lambda der: pytest.fail("cache was not used"))
    assert len(split_bundle(TWO_ROOTS, paths.cache)) == 2


def test_split_bundle_ignores_corrupt_cache(paths: Paths) -> None:
    paths.cache.mkdir(parents=True)
    key = hashlib.sha256(TWO_ROOTS.encode()).hexdigest()[:16]
    (paths.cache / f"parsed-{key}.json").write_text(json.dumps({"certs": [{"der": 1}]}))
    assert len(split_bundle(TWO_ROOTS, paths.cache)) == 2


def test_split_bundle_ignores_legacy_list_cache(paths: Paths) -> None:
    paths.cache.mkdir(parents=True)
    key = hashlib.sha256(TWO_ROOTS.encode()).hexdigest()[:16]
    (paths.cache / f"parsed-{key}.json").write_text("[]")
    assert len(split_bundle(TWO_ROOTS, paths.cache)) == 2


def test_split_bundle_rejects_empty_text() -> None:
    with pytest.raises(ToolError, match="no certificates"):
        split_bundle("nothing here")


def test_split_bundle_rejects_unreadable_certificate() -> None:
    broken = "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----"
    with pytest.raises(ToolError, match="unreadable certificate"):
        split_bundle(broken)


def test_prune_keeps_the_newest_files(paths: Paths) -> None:
    paths.cache.mkdir(parents=True)
    for index in range(5):
        path = paths.cache / f"parsed-{index}.json"
        path.write_text("{}")
        os.utime(path, (1000 + index, 1000 + index))
    prune_parsed_cache(paths.cache, now=datetime.fromtimestamp(1004, UTC))
    remaining = sorted(path.name for path in paths.cache.glob("parsed-*.json"))
    assert remaining == ["parsed-2.json", "parsed-3.json", "parsed-4.json"]


def test_prune_drops_old_files(paths: Paths) -> None:
    paths.cache.mkdir(parents=True)
    for index in range(2):
        path = paths.cache / f"parsed-old-{index}.json"
        path.write_text("{}")
        os.utime(path, (1000, 1000))
    prune_parsed_cache(paths.cache, now=datetime.fromtimestamp(1000 + 86400 * 31, UTC))
    assert list(paths.cache.glob("parsed-*.json")) == []


def test_validate_flags_non_root_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bundle_module, "MIN_ROOTS", 1)
    leaf = make_cert(subject="CN=Leaf", issuer="CN=Root")
    assert any("self-signed" in problem for problem in validate_bundle([leaf]))


def test_validate_rejects_empty_bundle() -> None:
    assert validate_bundle([])


def test_validate_flags_duplicates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bundle_module, "MIN_ROOTS", 1)
    cert = make_cert(der=b"same")
    assert any("duplicate" in problem for problem in validate_bundle([cert, cert]))


def test_validate_flags_expired_roots(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bundle_module, "MIN_ROOTS", 1)
    expired = make_cert(not_after=datetime(2001, 1, 1, tzinfo=UTC))
    assert any("expired" in problem for problem in validate_bundle([expired]))


def test_validate_accepts_a_single_fresh_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bundle_module, "MIN_ROOTS", 1)
    assert validate_bundle([make_cert()]) == []


@pytest.mark.parametrize(
    "url",
    [
        "http://curl.se/ca/cacert.pem",
        "https://evil.example/cacert.pem",
        "ftp://curl.se/ca/cacert.pem",
    ],
)
def test_assert_trusted_url_rejects(url: str) -> None:
    with pytest.raises(ToolError, match="untrusted URL"):
        assert_trusted_url(url)


def test_assert_trusted_url_accepts_known_sources() -> None:
    assert_trusted_url("https://curl.se/ca/cacert.pem")
    assert_trusted_url("https://raw.githubusercontent.com/certifi/python-certifi/x.pem")


def test_bundle_age_formatting() -> None:
    certs: list = []
    assert Bundle(certs, "x", None, "").age(now=NOW) == "unknown"
    assert Bundle(certs, "x", NOW - timedelta(minutes=5), "").age(now=NOW) == "5m old"
    assert Bundle(certs, "x", NOW - timedelta(hours=3), "").age(now=NOW) == "3h old"
    assert Bundle(certs, "x", NOW - timedelta(days=4), "").age(now=NOW) == "4d old"


def write_cache(paths: Paths, text: str, *, fetched_at: datetime) -> None:
    paths.cache.mkdir(parents=True, exist_ok=True)
    paths.cacert_pem.write_text(text)
    paths.cacert_meta.write_text(
        json.dumps({"source": "cache-test", "fetched_at": fetched_at.isoformat()})
    )


def test_fresh_cache_does_not_touch_the_network(paths: Paths) -> None:
    write_cache(paths, ROOT_A_TEXT, fetched_at=NOW)
    http = FakeHttp()
    store = BundleStore(paths, http, now=lambda: NOW)
    bundle = store.get()
    assert bundle.origin == "cache-test"
    assert len(bundle) == 1
    assert http.calls == []


def test_stale_cache_downloads_and_records_provenance(
    paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bundle_module, "MIN_ROOTS", 1)
    write_cache(paths, ROOT_A_TEXT, fetched_at=NOW - timedelta(days=2))
    http = FakeHttp({CA_SOURCES[0].url: (ROOT_A_TEXT.encode(), {"ETag": '"abc"'})})
    store = BundleStore(paths, http, now=lambda: NOW)

    bundle = store.get()

    assert bundle.origin == "curl.se"
    meta = json.loads(paths.cacert_meta.read_text())
    assert meta["etag"] == '"abc"'
    assert meta["fetched_at"] == NOW.isoformat(timespec="seconds")


def test_304_updates_fetched_at_and_keeps_the_bundle(
    paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bundle_module, "MIN_ROOTS", 1)
    write_cache(paths, ROOT_A_TEXT, fetched_at=NOW - timedelta(days=2))
    http = FakeHttp({CA_SOURCES[0].url: (None, {})})
    store = BundleStore(paths, http, now=lambda: NOW)

    bundle = store.get(refresh=True)

    assert len(bundle) == 1
    assert paths.cacert_pem.read_text() == ROOT_A_TEXT
    meta = json.loads(paths.cacert_meta.read_text())
    assert meta["fetched_at"] == NOW.isoformat(timespec="seconds")


def test_rejected_source_falls_back_to_the_next(
    paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bundle_module, "MIN_ROOTS", 1)
    http = FakeHttp(
        {
            CA_SOURCES[0].url: (b"garbage", {}),
            CA_SOURCES[1].url: (ROOT_B_TEXT.encode(), {}),
        }
    )
    store = BundleStore(paths, http, now=lambda: NOW)

    bundle = store.get(quiet=True)

    assert bundle.origin == "certifi"
    assert [cert.common_name for cert in bundle.certs] == ["Test Root Beta"]


def test_rejected_download_keeps_the_cached_copy(
    paths: Paths, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bundle_module, "MIN_ROOTS", 1)
    write_cache(paths, ROOT_A_TEXT, fetched_at=NOW - timedelta(days=2))
    http = FakeHttp({source.url: (b"garbage", {}) for source in CA_SOURCES})
    store = BundleStore(paths, http, now=lambda: NOW)

    bundle = store.get(refresh=True, quiet=True)

    assert [cert.common_name for cert in bundle.certs] == ["Test Root Alpha"]
    assert paths.cacert_pem.read_text() == ROOT_A_TEXT


def test_no_sources_and_no_cache_is_an_error(
    paths: Paths, capsys: pytest.CaptureFixture[str]
) -> None:
    store = BundleStore(paths, FakeHttp({}), now=lambda: NOW)
    with pytest.raises(ToolError, match="cannot obtain a CA bundle"):
        store.get()
    assert "warning:" in capsys.readouterr().err


def test_local_bundle_is_validated_and_used(
    paths: Paths, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bundle_module, "MIN_ROOTS", 1)
    local = tmp_path / "cacert.pem"
    local.write_text(ROOT_A_TEXT)
    store = BundleStore(paths, FakeHttp(), now=lambda: NOW)

    bundle = store.get(local_path=local)

    assert bundle.origin == str(local)
    assert len(bundle) == 1


def test_missing_local_bundle_is_an_error(paths: Paths, tmp_path) -> None:
    store = BundleStore(paths, FakeHttp(), now=lambda: NOW)
    with pytest.raises(ToolError, match="bundle file not found"):
        store.get(local_path=tmp_path / "nope.pem")


def test_invalid_local_bundle_is_an_error(paths: Paths, tmp_path) -> None:
    local = tmp_path / "cacert.pem"
    local.write_text("not a bundle")
    store = BundleStore(paths, FakeHttp(), now=lambda: NOW)
    with pytest.raises(ToolError):
        store.get(local_path=local)
