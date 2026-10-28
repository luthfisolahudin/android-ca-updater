"""Persisted record of the user CAs this tool installed per device."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypedDict

from .certs import Cert
from .errors import ToolError
from .process import read_json, write_atomic

STATE_VERSION = 1


class TrackedRoot(TypedDict):
    name: str | None
    sha1: str | None


class StateStore:
    """Reads and writes `state.json`, tolerating the legacy unversioned shape."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> dict[str, Any]:
        payload = read_json(self.path)
        if payload is None:
            return {"version": STATE_VERSION, "devices": {}}

        version = payload.get("version")
        if isinstance(version, int) and version > STATE_VERSION:
            raise ToolError(
                f"{self.path} was written by a newer android-ca-updater "
                f"(schema {version}, supported {STATE_VERSION})"
            )
        if not isinstance(payload.get("devices"), dict):
            payload["devices"] = {}
        payload["version"] = STATE_VERSION
        return payload

    def save(self, state: dict[str, Any]) -> None:
        state["version"] = STATE_VERSION
        write_atomic(self.path, json.dumps(state, indent=2))

    def _devices(self, state: dict[str, Any]) -> dict[str, Any]:
        devices: dict[str, Any] = state["devices"]
        return devices

    def tracked(self, serial: str) -> dict[str, TrackedRoot]:
        entry = self._devices(self.load()).get(serial, {})
        installed = entry.get("installed", {}) if isinstance(entry, dict) else {}
        tracked: dict[str, TrackedRoot] = {}
        for fingerprint, value in installed.items():
            if isinstance(value, str):
                tracked[fingerprint] = {"name": value, "sha1": None}
            elif isinstance(value, dict):
                name = value.get("name")
                sha1 = value.get("sha1")
                tracked[fingerprint] = {
                    "name": name if isinstance(name, str) else None,
                    "sha1": sha1 if isinstance(sha1, str) else None,
                }
        return tracked

    def track(self, serial: str, cert: Cert, name: str) -> None:
        state = self.load()
        devices = self._devices(state)
        entry = devices.setdefault(serial, {"installed": {}})
        entry["installed"][cert.fingerprint] = {"name": name, "sha1": cert.sha1}
        entry["updated_at"] = _timestamp()
        self.save(state)

    def untrack(self, serial: str, fingerprint: str) -> None:
        state = self.load()
        entry = self._devices(state).get(serial)
        if not isinstance(entry, dict):
            return
        entry.get("installed", {}).pop(fingerprint, None)
        entry["updated_at"] = _timestamp()
        self.save(state)

    def backfill_sha1(
        self, serial: str, tracked: dict[str, TrackedRoot], certs: Sequence[Cert]
    ) -> None:
        missing = [fingerprint for fingerprint, info in tracked.items() if not info.get("sha1")]
        if not missing:
            return
        by_fingerprint = {cert.fingerprint: cert for cert in certs}
        updated = False
        for fingerprint in missing:
            cert = by_fingerprint.get(fingerprint)
            if cert is None:
                continue
            tracked[fingerprint]["sha1"] = cert.sha1
            updated = True
        if not updated:
            return

        state = self.load()
        entry = self._devices(state).setdefault(serial, {"installed": {}})
        installed = entry.setdefault("installed", {})
        for fingerprint, info in tracked.items():
            installed[fingerprint] = {"name": info.get("name"), "sha1": info.get("sha1")}
        entry["updated_at"] = _timestamp()
        self.save(state)


def _timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
