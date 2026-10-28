from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from android_ca_updater.certs import Cert, parse_cert, pem_to_der
from android_ca_updater.config import Paths
from android_ca_updater.state import StateStore

FIXTURES = Path(__file__).parent / "fixtures"

requires_openssl = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl is required for this test"
)


def load_pem_cert(name: str) -> Cert:
    return parse_cert(pem_to_der((FIXTURES / name).read_text(encoding="utf-8")))


@pytest.fixture(scope="session")
def root_a() -> Cert:
    return load_pem_cert("root-a.pem")


@pytest.fixture(scope="session")
def root_b() -> Cert:
    return load_pem_cert("root-b.pem")


@pytest.fixture(scope="session")
def leaf_a() -> Cert:
    return load_pem_cert("leaf-a.pem")


@pytest.fixture
def paths(tmp_path: Path) -> Paths:
    return Paths(cache=tmp_path / "cache", state=tmp_path / "state" / "state.json")


@pytest.fixture
def state_store(paths: Paths) -> StateStore:
    return StateStore(paths.state)


@pytest.fixture
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.sleep", lambda _seconds: None)
