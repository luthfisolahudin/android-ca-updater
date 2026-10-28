from __future__ import annotations

import subprocess

import pytest

from android_ca_updater import tls
from android_ca_updater.certs import Cert
from android_ca_updater.tls import resolve_anchor, verify_chain_with_cafile
from conftest import FIXTURES, requires_openssl

pytestmark = requires_openssl


def test_accepts_chain_signed_by_the_given_anchor(leaf_a: Cert) -> None:
    assert verify_chain_with_cafile([leaf_a], FIXTURES / "root-a.pem")


def test_rejects_chain_signed_by_another_anchor(leaf_a: Cert) -> None:
    assert not verify_chain_with_cafile([leaf_a], FIXTURES / "root-b.pem")


def test_missing_anchor_file_is_false(leaf_a: Cert) -> None:
    assert not verify_chain_with_cafile([leaf_a], FIXTURES / "missing.pem")


def test_empty_chain_is_false() -> None:
    assert not verify_chain_with_cafile([], FIXTURES / "root-a.pem")


def test_resolve_anchor_returns_the_issuer(leaf_a: Cert, root_a: Cert, root_b: Cert) -> None:
    assert resolve_anchor([leaf_a], [root_b, root_a]) == root_a


def test_resolve_anchor_returns_none_when_unknown(leaf_a: Cert, root_b: Cert) -> None:
    assert resolve_anchor([leaf_a], [root_b]) is None


def test_resolve_anchor_with_empty_chain(root_a: Cert) -> None:
    assert resolve_anchor([], [root_a]) is None


def completed(stdout: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr=b"")


def test_fetch_chain_parses_openssl_output(monkeypatch: pytest.MonkeyPatch) -> None:
    pem = (FIXTURES / "root-a.pem").read_bytes()
    monkeypatch.setattr(tls, "run", lambda *args, **kwargs: completed(pem))

    chain = tls.fetch_chain("example.com")

    assert [cert.common_name for cert in chain] == ["Test Root Alpha"]


def test_fetch_chain_returns_empty_without_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tls, "run", lambda *args, **kwargs: completed(b""))
    assert tls.fetch_chain("example.com") == []


def test_fetch_chain_skips_unreadable_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    broken = b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"
    monkeypatch.setattr(tls, "run", lambda *args, **kwargs: completed(broken))
    assert tls.fetch_chain("example.com") == []
