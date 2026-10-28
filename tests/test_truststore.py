from __future__ import annotations

import hashlib
import json
from pathlib import Path

from android_ca_updater.certs import Cert, to_json
from android_ca_updater.config import Paths
from android_ca_updater.truststore import build_index, load_system_store
from conftest import FIXTURES, requires_openssl
from fakes import FakeDevice

pytestmark = requires_openssl


def cache_dir(paths: Paths, device: FakeDevice) -> Path:
    key = hashlib.sha256(device.fingerprint.encode()).hexdigest()[:16]
    return paths.devices / key


def test_build_index_and_lookup(root_a: Cert, root_b: Cert) -> None:
    index = build_index([root_a])
    assert len(index) == 1
    assert index.has(root_a)
    assert not index.has(root_b)


def test_has_falls_back_to_the_public_key(root_a: Cert) -> None:
    clone = Cert(
        der=b"different-der",
        subject=root_a.subject,
        issuer=root_a.issuer,
        not_after=root_a.not_after,
        spki_cache=root_a.spki_sha256,
    )
    assert build_index([root_a]).has(clone)


def test_trusts_chain_requires_a_bundle_path(leaf_a: Cert) -> None:
    assert not build_index([leaf_a]).trusts_chain([leaf_a])


def test_load_uses_the_cached_store(paths: Paths, root_a: Cert) -> None:
    device = FakeDevice()
    target = cache_dir(paths, device)
    target.mkdir(parents=True)
    (target / "store.json").write_text(json.dumps([to_json(root_a)]))
    (target / "store.pem").write_bytes(root_a.pem)

    index = load_system_store(device, paths)

    assert index is not None
    assert len(index) == 1
    assert device.pulls == []


def test_load_returns_none_when_the_pull_fails(paths: Paths) -> None:
    assert load_system_store(FakeDevice(), paths) is None


class PullDevice(FakeDevice):
    def __init__(self, pem: Path) -> None:
        super().__init__()
        self.pem = pem

    def pull(self, remote: str, local: Path) -> None:
        self.pulls.append((remote, local))
        local.mkdir(parents=True, exist_ok=True)
        (local / "root.pem").write_bytes(self.pem.read_bytes())


def test_load_pulls_parses_and_caches(paths: Paths) -> None:
    device = PullDevice(FIXTURES / "root-a.pem")

    index = load_system_store(device, paths)

    assert index is not None
    assert len(index) == 1
    target = cache_dir(paths, device)
    assert (target / "store.pem").exists()
    assert (target / "store.json").exists()

    load_system_store(device, paths)
    assert len(device.pulls) == 1
