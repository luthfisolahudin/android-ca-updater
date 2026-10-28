"""Constants and runtime paths.

Paths are resolved at call time rather than import time so tests and callers can
point the tool at an isolated cache or state directory.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

APP_NAME = "android-ca-updater"

BUNDLE_MAX_AGE = timedelta(days=1)

DEVICE_DIR = "/sdcard/Download/android-ca-updater"
CERT_INSTALLER_PKG = "com.android.certinstaller"
CERT_INSTALLER_ACTIVITY = f"{CERT_INSTALLER_PKG}/.CertInstallerMain"
CHROME_PACKAGE = "com.android.chrome"
CHROME_ACTIVITY = "com.android.chrome/com.google.android.apps.chrome.Main"
UI_DUMP_PATH = "/sdcard/android-ca-updater-ui.xml"

DEFAULT_HOSTS = (
    "github.com",
    "raw.githubusercontent.com",
    "api.github.com",
    "f-droid.org",
    "letsencrypt.org",
    "registry.npmjs.org",
    "pypi.org",
    "gitlab.com",
    "x.com",
    "notion.so",
)

OK_LABELS = ("ok", "oke", "simpan", "save", "确定", "aceptar")
SCREEN_LOCK_LABELS = ("kunci layar", "screen lock")

CERTDATA_URL = (
    "https://raw.githubusercontent.com/mozilla/gecko-dev/master/"
    "security/nss/lib/ckfw/builtins/certdata.txt"
)
TRUSTED_FOR_TLS = "CKT_NSS_TRUSTED_DELEGATOR"
MIN_ROOTS = 50

CREDENTIAL_ACTIVITIES = (
    "com.android.settings/.Settings$TrustedCredentialsSettingsActivity",
    "com.android.settings/.TrustedCredentialsSettings",
)
SECURITY_SETTINGS_ACTION = "android.settings.SECURITY_SETTINGS"
USER_TAB_LABELS = ("pengguna", "user")
CREDENTIAL_LABELS = (
    "trusted credentials",
    "kredensial tepercaya",
    "sertifikat tepercaya",
    "credential storage",
    "penyimpanan kredensial",
    "certificates",
    "sertifikat",
)
REMOVE_LABELS = ("remove", "uninstall", "hapus", "delete")

PARSED_CACHE_KEEP = 3
PARSED_CACHE_MAX_AGE = timedelta(days=30)


@dataclass(frozen=True)
class Paths:
    """Cache and state locations for one run."""

    cache: Path
    state: Path

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Paths:
        source = os.environ if env is None else env
        home = Path(source["HOME"]) if source.get("HOME") else Path.home()

        cache_home = source.get("XDG_CACHE_HOME") or str(home / ".cache")
        state_home = source.get("XDG_STATE_HOME") or str(home / ".local" / "state")

        return cls(
            cache=Path(cache_home) / APP_NAME,
            state=Path(state_home) / APP_NAME / "state.json",
        )

    @property
    def cacert_pem(self) -> Path:
        return self.cache / "cacert.pem"

    @property
    def cacert_meta(self) -> Path:
        return self.cache / "cacert.json"

    @property
    def certdata_txt(self) -> Path:
        return self.cache / "certdata.txt"

    @property
    def certdata_meta(self) -> Path:
        return self.cache / "certdata.json"

    @property
    def devices(self) -> Path:
        return self.cache / "devices"
