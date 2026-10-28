"""The device's system trust store as a searchable index."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from .adb import AdbDevice
from .certs import Cert, from_json, parse_cert, pem_to_der, to_json
from .config import Paths
from .errors import ToolError
from .process import write_atomic


@dataclass
class StoreIndex:
    by_fingerprint: dict[str, Cert]
    by_subject: dict[str, list[Cert]]
    bundle_path: Path | None = None

    def has(self, cert: Cert) -> bool:
        if cert.fingerprint in self.by_fingerprint:
            return True
        for candidate in self.by_subject.get(cert.subject, []):
            if candidate.spki_sha256 == cert.spki_sha256:
                return True
        return False

    def trusts_chain(self, chain: list[Cert]) -> bool:
        from .tls import verify_chain_with_cafile

        if not chain or self.bundle_path is None:
            return False
        return verify_chain_with_cafile(chain, self.bundle_path)

    def __len__(self) -> int:
        return len(self.by_fingerprint)


def build_index(certs: list[Cert], bundle_path: Path | None = None) -> StoreIndex:
    by_fingerprint = {cert.fingerprint: cert for cert in certs}
    by_subject: dict[str, list[Cert]] = {}
    for cert in certs:
        by_subject.setdefault(cert.subject, []).append(cert)
    return StoreIndex(by_fingerprint=by_fingerprint, by_subject=by_subject, bundle_path=bundle_path)


def load_system_store(device: AdbDevice, paths: Paths) -> StoreIndex | None:
    key = hashlib.sha256(device.fingerprint.encode()).hexdigest()[:16]
    device_dir = paths.devices / key
    cache_path = device_dir / "store.json"
    bundle_path = device_dir / "store.pem"

    if cache_path.exists() and bundle_path.exists():
        try:
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
            cached_certs = [from_json(item) for item in payload]
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            pass
        else:
            return build_index(cached_certs, bundle_path)

    target = device_dir / "cacerts"
    if target.exists():
        shutil.rmtree(target)
    try:
        device.pull("/system/etc/security/cacerts", target)
    except ToolError:
        return None

    certs: list[Cert] = []
    for file in sorted(target.rglob("*")):
        if not file.is_file():
            continue
        try:
            text = file.read_text(encoding="utf-8", errors="ignore")
            if "BEGIN CERTIFICATE" not in text:
                continue
            certs.append(parse_cert(pem_to_der(text)))
        except (ValueError, ToolError, OSError):
            continue
    if not certs:
        return None
    write_atomic(bundle_path, b"".join(cert.pem for cert in certs))
    write_atomic(cache_path, json.dumps([to_json(cert) for cert in certs]))
    return build_index(certs, bundle_path)
