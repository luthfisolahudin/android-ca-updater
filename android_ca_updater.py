#!/usr/bin/env python3
"""android-ca-updater - install modern root CAs on legacy Android devices over adb.

Android releases before 7.1.1 ship a frozen system trust store with no update
mechanism, so sites that chain to newer roots (Let's Encrypt, Google Trust
Services, Amazon, ...) fail with ERR_CERT_AUTHORITY_INVALID. This tool finds the
missing roots, downloads them from Mozilla's CA bundle, and installs them as
user CAs by driving Android's own certificate installer over adb.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

__version__ = "0.1.0"

BUNDLE_MAX_AGE = timedelta(days=1)
DEVICE_DIR = "/sdcard/Download/android-ca-updater"
CERT_INSTALLER_PKG = "com.android.certinstaller"
CERT_INSTALLER_ACTIVITY = f"{CERT_INSTALLER_PKG}/.CertInstallerMain"
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

PEM_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)

CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "android-ca-updater"
STATE_FILE = (
    Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    / "android-ca-updater"
    / "state.json"
)


class ToolError(RuntimeError):
    pass


class NeedsUnlock(ToolError):
    pass


class NeedsScreenLock(ToolError):
    pass


# --------------------------------------------------------------------------- io


def run(
    cmd: list[str],
    *,
    data: bytes | None = None,
    timeout: int = 120,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(cmd, input=data, capture_output=True, timeout=timeout, env=env)
    except FileNotFoundError as exc:
        raise ToolError(f"command not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"timed out: {' '.join(cmd[:4])}") from exc
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or b"").decode("utf-8", "replace").strip()
        detail = detail.splitlines()[0] if detail else ""
        raise ToolError(f"{' '.join(cmd[:3])}: {detail[:400]}")
    return proc


def write_atomic(path: Path, data: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    if isinstance(data, str):
        tmp.write_text(data, encoding="utf-8")
    else:
        tmp.write_bytes(data)
    tmp.replace(path)


# --------------------------------------------------------------------- certificates


def parse_openssl_date(value: str) -> datetime:
    cleaned = re.sub(r"\s+", " ", value.strip())
    return datetime.strptime(cleaned, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)


@dataclass
class Cert:
    der: bytes
    subject: str
    issuer: str
    not_after: datetime
    _spki: str | None = None

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.der).hexdigest()

    @property
    def pem(self) -> bytes:
        return ssl.DER_cert_to_PEM_cert(self.der).encode()

    @property
    def common_name(self) -> str:
        match = re.search(r"(?:^|,)CN=((?:\\.|[^,])*)", self.subject)
        if not match:
            return self.subject or "unknown"
        return match.group(1).replace("\\,", ",").replace('\\"', '"')

    @property
    def spki_sha256(self) -> str:
        if self._spki is None:
            pubkey = run(["openssl", "x509", "-noout", "-pubkey"], data=self.pem).stdout
            spki = run(["openssl", "pkey", "-pubin", "-outform", "DER"], data=pubkey).stdout
            self._spki = hashlib.sha256(spki).hexdigest()
        return self._spki


def pem_to_der(text: str) -> bytes:
    match = PEM_BLOCK.search(text)
    if not match:
        raise ValueError("no PEM certificate found")
    return ssl.PEM_cert_to_DER_cert(match.group(0))


def parse_cert(der: bytes) -> Cert:
    pem = ssl.DER_cert_to_PEM_cert(der).encode()
    out = run(
        ["openssl", "x509", "-noout", "-subject", "-issuer", "-enddate", "-nameopt", "RFC2253"],
        data=pem,
    ).stdout.decode("utf-8", "replace")
    subject = issuer = ""
    not_after = datetime.now(timezone.utc)
    for line in out.splitlines():
        if line.startswith("subject="):
            subject = line[len("subject=") :].strip()
        elif line.startswith("issuer="):
            issuer = line[len("issuer=") :].strip()
        elif line.startswith("notAfter="):
            not_after = parse_openssl_date(line[len("notAfter=") :])
    return Cert(der=der, subject=subject, issuer=issuer, not_after=not_after)


def to_json(cert: Cert) -> dict:
    return {
        "der": base64.b64encode(cert.der).decode("ascii"),
        "subject": cert.subject,
        "issuer": cert.issuer,
        "not_after": cert.not_after.isoformat(),
        "spki": cert._spki,
    }


def from_json(payload: dict) -> Cert:
    cert = Cert(
        der=base64.b64decode(payload["der"]),
        subject=payload["subject"],
        issuer=payload["issuer"],
        not_after=datetime.fromisoformat(payload["not_after"]),
    )
    cert._spki = payload.get("spki")
    return cert


# ------------------------------------------------------------------ mozilla bundle


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    description: str


CA_SOURCES = (
    Source(
        name="curl.se",
        url="https://curl.se/ca/cacert.pem",
        description="Mozilla NSS certdata, published by the curl project",
    ),
    Source(
        name="certifi",
        url="https://raw.githubusercontent.com/certifi/python-certifi/master/certifi/cacert.pem",
        description="Mozilla NSS certdata, published by python-certifi",
    ),
)
TRUSTED_HOSTS = frozenset({"curl.se", "raw.githubusercontent.com"})
MIN_ROOTS = 50


@dataclass
class Bundle:
    certs: list[Cert]
    origin: str
    fetched_at: datetime | None
    sha256: str

    def __len__(self) -> int:
        return len(self.certs)

    def age(self) -> str:
        if self.fetched_at is None:
            return "unknown"
        delta = datetime.now(timezone.utc) - self.fetched_at
        if delta < timedelta(hours=1):
            return f"{delta.seconds // 60}m old"
        if delta < timedelta(days=1):
            return f"{delta.seconds // 3600}h old"
        return f"{delta.days}d old"


def assert_trusted_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in TRUSTED_HOSTS:
        raise ToolError(f"refusing to download CA bundle from an untrusted URL: {url}")


def http_get(url: str, etag: str | None, last_modified: str | None) -> tuple[bytes | None, dict[str, str]]:
    assert_trusted_url(url)
    headers = {"User-Agent": f"android-ca-updater/{__version__}"}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return None, {}
        raise


def validate_bundle(certs: list[Cert]) -> list[str]:
    problems: list[str] = []
    if len(certs) < MIN_ROOTS:
        problems.append(f"only {len(certs)} roots, expected at least {MIN_ROOTS}")
    if not certs:
        return problems or ["empty bundle"]
    not_self_signed = [cert for cert in certs if cert.subject != cert.issuer]
    if not_self_signed:
        problems.append(f"{len(not_self_signed)} certificate(s) are not self-signed roots")
    fingerprints = [cert.fingerprint for cert in certs]
    if len(fingerprints) != len(set(fingerprints)):
        problems.append("duplicate certificates")
    now = datetime.now(timezone.utc)
    expired = [cert for cert in certs if cert.not_after <= now]
    if expired:
        problems.append(f"{len(expired)} expired root(s)")
    return problems


def split_bundle(pem_text: str) -> list[Cert]:
    cache_key = hashlib.sha256(pem_text.encode()).hexdigest()[:16]
    cache_path = CACHE_DIR / f"parsed-{cache_key}.json"
    if cache_path.exists():
        try:
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
            return [from_json(item) for item in payload]
        except (json.JSONDecodeError, KeyError):
            pass
    blocks = PEM_BLOCK.findall(pem_text)
    if not blocks:
        raise ToolError("bundle contains no certificates")
    certs: list[Cert] = []
    for block in blocks:
        try:
            certs.append(parse_cert(ssl.PEM_cert_to_DER_cert(block)))
        except (ValueError, ToolError) as exc:
            raise ToolError(f"bundle contains an unreadable certificate: {exc}") from exc
    write_atomic(cache_path, json.dumps([to_json(cert) for cert in certs]))
    return certs


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def fetch_bundle(
    refresh: bool = False,
    quiet: bool = False,
    max_age: timedelta = BUNDLE_MAX_AGE,
    local_path: Path | None = None,
) -> Bundle:
    if local_path is not None:
        if not local_path.exists():
            raise ToolError(f"bundle file not found: {local_path}")
        pem_text = local_path.read_text(encoding="utf-8", errors="replace")
        certs = split_bundle(pem_text)
        problems = validate_bundle(certs)
        if problems:
            raise ToolError(f"{local_path} is not a usable CA bundle: {', '.join(problems)}")
        return Bundle(
            certs=certs,
            origin=str(local_path),
            fetched_at=datetime.fromtimestamp(local_path.stat().st_mtime, timezone.utc),
            sha256=hashlib.sha256(pem_text.encode()).hexdigest(),
        )

    pem_path = CACHE_DIR / "cacert.pem"
    meta_path = CACHE_DIR / "cacert.json"
    meta: dict = {}
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            meta = {}

    cached_at = parse_timestamp(meta.get("fetched_at"))
    is_fresh = cached_at is not None and datetime.now(timezone.utc) - cached_at < max_age

    if refresh or not is_fresh or not pem_path.exists():
        for source in CA_SOURCES:
            try:
                body, headers = http_get(source.url, meta.get("etag"), meta.get("last_modified"))
            except (OSError, urllib.error.URLError) as exc:
                if not quiet:
                    print(f"warning: {source.name} unavailable ({exc})", file=sys.stderr)
                continue
            if body is None:
                meta["fetched_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
                write_atomic(meta_path, json.dumps(meta, indent=2))
                if not quiet:
                    print(f"CA bundle unchanged ({source.name}, not modified)")
                break
            text = body.decode("utf-8", "replace")
            try:
                certs = split_bundle(text)
            except ToolError as exc:
                if not quiet:
                    print(f"warning: rejected {source.name} bundle: {exc}", file=sys.stderr)
                continue
            problems = validate_bundle(certs)
            if problems:
                if not quiet:
                    print(f"warning: rejected {source.name} bundle: {', '.join(problems)}", file=sys.stderr)
                continue
            write_atomic(pem_path, text)
            meta = {
                "source": source.name,
                "url": source.url,
                "description": source.description,
                "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "etag": headers.get("ETag"),
                "last_modified": headers.get("Last-Modified"),
                "sha256": hashlib.sha256(text.encode()).hexdigest(),
            }
            write_atomic(meta_path, json.dumps(meta, indent=2))
            if not quiet:
                print(f"CA bundle updated from {source.name}: {len(certs)} roots")
            break

    if not pem_path.exists():
        raise ToolError("cannot obtain a CA bundle and no cached copy exists")

    pem_text = pem_path.read_text(encoding="utf-8", errors="replace")
    certs = split_bundle(pem_text)
    return Bundle(
        certs=certs,
        origin=meta.get("source", "cache"),
        fetched_at=parse_timestamp(meta.get("fetched_at")),
        sha256=hashlib.sha256(pem_text.encode()).hexdigest(),
    )



# --------------------------------------------------------------------------- chains


def fetch_chain(host: str, port: int = 443) -> list[Cert]:
    proc = run(
        ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-showcerts"],
        data=b"",
        timeout=30,
        check=False,
    )
    if not proc.stdout:
        return []
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        proc.stdout.decode("utf-8", "replace"),
        re.S,
    )
    certs: list[Cert] = []
    for block in blocks:
        try:
            certs.append(parse_cert(ssl.PEM_cert_to_DER_cert(block)))
        except (ValueError, ToolError):
            continue
    return certs


def verify_chain_with_cafile(chain: list[Cert], ca_file: Path) -> bool:
    if not chain or not ca_file.exists():
        return False
    with tempfile.TemporaryDirectory() as tmp:
        leaf = Path(tmp) / "leaf.pem"
        leaf.write_bytes(chain[0].pem)
        empty_dir = Path(tmp) / "empty-ca-dir"
        empty_dir.mkdir()
        isolated_env = {
            **os.environ,
            "SSL_CERT_FILE": str(ca_file),
            "SSL_CERT_DIR": str(empty_dir),
        }
        cmd = ["openssl", "verify", "-partial_chain", "-CAfile", str(ca_file)]
        if len(chain) > 1:
            untrusted = Path(tmp) / "untrusted.pem"
            untrusted.write_bytes(b"".join(cert.pem for cert in chain[1:]))
            cmd += ["-untrusted", str(untrusted)]
        cmd.append(str(leaf))
        proc = run(cmd, check=False, env=isolated_env)
        return proc.returncode == 0


def verify_with_anchor(chain: list[Cert], anchor: Cert) -> bool:
    if not chain:
        return False
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "root.pem"
        root.write_bytes(anchor.pem)
        return verify_chain_with_cafile(chain, root)


def resolve_anchor(chain: list[Cert], bundle: list[Cert]) -> Cert | None:
    if not chain:
        return None
    issuer = chain[-1].issuer
    for candidate in bundle:
        if candidate.subject == issuer and verify_with_anchor(chain, candidate):
            return candidate
    return None


# --------------------------------------------------------------------------- device


def find_adb() -> str:
    override = os.environ.get("ADB")
    if override:
        return override
    found = shutil.which("adb")
    if found:
        return found
    for candidate in (
        Path.home() / "Android/Sdk/platform-tools/adb",
        Path("/usr/lib/android-sdk/platform-tools/adb"),
        Path("/opt/android-sdk/platform-tools/adb"),
    ):
        if candidate.exists():
            return str(candidate)
    raise ToolError("adb not found: install Android platform-tools or set $ADB")


class Device:
    def __init__(self, adb: str, serial: str):
        self.adb = adb
        self.serial = serial

    def shell(self, command: str, timeout: int = 90) -> str:
        proc = run([self.adb, "-s", self.serial, "shell", command], timeout=timeout)
        return proc.stdout.decode("utf-8", "replace")

    def push(self, local: Path, remote: str) -> None:
        run([self.adb, "-s", self.serial, "push", str(local), remote])

    def pull(self, remote: str, local: Path) -> None:
        local.parent.mkdir(parents=True, exist_ok=True)
        run([self.adb, "-s", self.serial, "pull", remote, str(local)])

    def getprop(self, name: str) -> str:
        return self.shell(f"getprop {name}").strip()

    def logcat_clear(self) -> None:
        run([self.adb, "-s", self.serial, "logcat", "-c"], check=False)

    def logcat(self) -> str:
        proc = run([self.adb, "-s", self.serial, "logcat", "-d"], check=False, timeout=60)
        return proc.stdout.decode("utf-8", "replace")

    @property
    def model(self) -> str:
        return self.getprop("ro.product.model") or self.serial

    @property
    def android_release(self) -> str:
        return self.getprop("ro.build.version.release")

    @property
    def sdk(self) -> int:
        try:
            return int(self.getprop("ro.build.version.sdk"))
        except ValueError:
            return 0

    @property
    def fingerprint(self) -> str:
        return self.getprop("ro.build.fingerprint")

    def is_locked(self) -> bool:
        try:
            trust = self.shell("dumpsys trust")
        except ToolError:
            return False
        if re.search(r"deviceLocked=1", trust):
            return True
        return bool(re.search(r"mShowingLockscreen=true", self.shell("dumpsys window")))

    def ensure_unlocked(self) -> None:
        if self.is_locked():
            raise NeedsUnlock("device is locked - unlock the screen and try again")


def pick_device(adb: str, serial: str | None) -> Device:
    proc = run([adb, "devices"])
    serials = [
        line.split("\t")[0]
        for line in proc.stdout.decode().splitlines()[1:]
        if line.strip().endswith("device") and "\t" in line
    ]
    if serial:
        if serial not in serials:
            raise ToolError(f"device {serial} not connected")
        return Device(adb, serial)
    if not serials:
        raise ToolError("no adb device found - connect the phone with USB debugging enabled")
    if len(serials) > 1:
        raise ToolError(f"multiple devices connected, pass --serial: {', '.join(serials)}")
    return Device(adb, serials[0])


# ----------------------------------------------------------------------- store index


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
        if not chain or self.bundle_path is None:
            return False
        return verify_chain_with_cafile(chain, self.bundle_path)

    def __len__(self) -> int:
        return len(self.by_fingerprint)


def load_system_store(dev: Device) -> StoreIndex | None:
    key = hashlib.sha256(dev.fingerprint.encode()).hexdigest()[:16]
    device_dir = CACHE_DIR / "devices" / key
    cache_path = device_dir / "store.json"
    bundle_path = device_dir / "store.pem"
    if cache_path.exists() and bundle_path.exists():
        try:
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
            certs = [from_json(item) for item in payload]
            return _build_index(certs, bundle_path)
        except (json.JSONDecodeError, KeyError):
            pass

    target = device_dir / "cacerts"
    if target.exists():
        shutil.rmtree(target)
    try:
        dev.pull("/system/etc/security/cacerts", target)
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
    return _build_index(certs, bundle_path)


def _build_index(certs: list[Cert], bundle_path: Path | None = None) -> StoreIndex:
    by_fingerprint = {cert.fingerprint: cert for cert in certs}
    by_subject: dict[str, list[Cert]] = {}
    for cert in certs:
        by_subject.setdefault(cert.subject, []).append(cert)
    return StoreIndex(by_fingerprint=by_fingerprint, by_subject=by_subject, bundle_path=bundle_path)


# ---------------------------------------------------------------------------- state


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {"devices": {}}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"devices": {}}


def save_state(state: dict) -> None:
    write_atomic(STATE_FILE, json.dumps(state, indent=2))


def tracked_roots(serial: str) -> dict[str, str]:
    entry = load_state().get("devices", {}).get(serial, {})
    return entry.get("installed", {})


def track_root(serial: str, cert: Cert, name: str) -> None:
    state = load_state()
    devices = state.setdefault("devices", {})
    entry = devices.setdefault(serial, {"installed": {}})
    entry["installed"][cert.fingerprint] = name
    entry["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    save_state(state)


# ------------------------------------------------------------------------ ui driver


def ui_dump(dev: Device) -> ET.Element | None:
    dev.shell(f"rm -f {UI_DUMP_PATH}", timeout=30)
    try:
        dev.shell(f"uiautomator dump {UI_DUMP_PATH}", timeout=120)
        payload = dev.shell(f"cat {UI_DUMP_PATH}", timeout=60)
    except ToolError:
        return None
    if "hierarchy" not in payload:
        return None
    try:
        return ET.fromstring(payload)
    except ET.ParseError:
        return None


def ime_visible(dev: Device) -> bool:
    try:
        return "mInputShown=true" in dev.shell("dumpsys input_method", timeout=30)
    except ToolError:
        return False


def node_bounds(node: ET.Element) -> tuple[int, int] | None:
    raw = node.get("bounds", "")
    match = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", raw)
    if not match:
        return None
    left, top, right, bottom = (int(value) for value in match.groups())
    return (left + right) // 2, (top + bottom) // 2


def find_node(root: ET.Element | None, *, class_name: str | None = None, labels: tuple[str, ...] | None = None):
    if root is None:
        return None
    for node in root.iter("node"):
        if class_name and not node.get("class", "").endswith(class_name):
            continue
        if labels is not None:
            text = (node.get("text") or "").strip().lower()
            if text not in labels:
                continue
        return node
    return None


def current_focus(dev: Device) -> str:
    return dev.shell("dumpsys window | grep -E 'mCurrentFocus'")


def wait_for(predicate, timeout: float, interval: float = 0.5) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def safe_cert_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9 ._+-]", "", name)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned or "root-ca"


def install_root(dev: Device, cert: Cert, name: str, dry_run: bool = False) -> None:
    if cert.subject != cert.issuer:
        raise ToolError(f"refusing to install {cert.common_name}: not a self-signed root")
    if dry_run:
        return
    dev.ensure_unlocked()
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", safe_cert_name(name)).strip("-") or cert.fingerprint[:12]
    remote = f"{DEVICE_DIR}/{slug}.crt"

    dev.shell(f"mkdir -p {DEVICE_DIR}")
    with tempfile.TemporaryDirectory() as tmp:
        local = Path(tmp) / f"{slug}.crt"
        local.write_bytes(cert.der)
        dev.push(local, remote)

    dev.shell(
        f'am start -n {CERT_INSTALLER_ACTIVITY} -a android.intent.action.VIEW '
        f'-t application/x-x509-ca-cert -d "file://{remote}"'
    )
    if not wait_for(lambda: CERT_INSTALLER_PKG in current_focus(dev), timeout=15):
        raise ToolError("certificate installer did not open")

    dump = ui_dump(dev)
    if dump is None:
        raise ToolError("cannot read certificate installer UI")
    visible = " ".join((node.get("text") or "") for node in dump.iter("node")).lower()
    if "kunci layar" in visible or "screen lock" in visible:
        raise NeedsScreenLock(
            "Android requires a screen lock (PIN/pattern) before user CAs can be installed"
        )

    field = find_node(dump, class_name="EditText")
    if field is not None:
        center = node_bounds(field)
        if center is None:
            raise ToolError("cannot locate the certificate name field")
        dev.shell(f"input tap {center[0]} {center[1]}")
        wait_for(lambda: ime_visible(dev), timeout=6)
        typed_name = safe_cert_name(name)
        entry = None
        for _ in range(3):
            dev.shell(f'input text "{typed_name.replace(" ", "%s")}"')
            time.sleep(0.5)
            dump = ui_dump(dev)
            if dump is None:
                raise ToolError("certificate dialog closed while entering the name")
            entry = find_node(dump, class_name="EditText")
            if entry is not None and (entry.get("text") or "").strip():
                break
        if entry is None or not (entry.get("text") or "").strip():
            raise ToolError("could not type a certificate name into the installer")
        dev.shell("input keyevent 4")
        time.sleep(0.8)
        if CERT_INSTALLER_PKG not in current_focus(dev):
            raise ToolError("certificate dialog closed while entering the name")
        dump = ui_dump(dev)
        if dump is None:
            raise ToolError("certificate dialog closed unexpectedly")

    button = find_node(dump, class_name="Button", labels=OK_LABELS)
    if button is None:
        raise ToolError("cannot find the confirm button in the certificate installer")
    center = node_bounds(button)
    if center:
        dev.shell(f"input tap {center[0]} {center[1]}")

    if not wait_for(lambda: CERT_INSTALLER_PKG not in current_focus(dev), timeout=25):
        leftover = ui_dump(dev)
        visible = ""
        if leftover is not None:
            visible = " ".join(node.get("text") or "" for node in leftover.iter("node")).strip()
        suffix = f": {visible[:160]}" if visible else ""
        raise ToolError(f"certificate installer did not finish{suffix}")
    track_root(dev.serial, cert, safe_cert_name(name))


# ------------------------------------------------------------------------ diagnostics


@dataclass
class HostResult:
    host: str
    anchor: Cert | None
    source: str
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.source in {"system", "user"}


def analyse_host(host: str, bundle: list[Cert], store: StoreIndex | None, tracked: dict[str, str]) -> HostResult:
    chain = fetch_chain(host)
    if not chain:
        return HostResult(host, None, "unreachable", "no TLS response")
    if store is not None and store.trusts_chain(chain):
        return HostResult(host, None, "system")
    anchor = resolve_anchor(chain, bundle)
    if anchor is None:
        return HostResult(host, None, "unknown", "cannot determine the anchor root")
    if anchor.not_after < datetime.now(timezone.utc):
        return HostResult(host, anchor, "expired", "anchor root expired")
    if anchor.fingerprint in tracked:
        return HostResult(host, anchor, "user")
    return HostResult(host, anchor, "missing")


def browser_check(dev: Device, host: str, wait: float = 4.0) -> tuple[bool | None, str]:
    try:
        dev.shell("pm list packages com.android.chrome | grep -q package")
    except ToolError:
        return None, "chrome not installed"
    dev.logcat_clear()
    dev.shell(
        f'am start -a android.intent.action.VIEW -d "https://{host}/?cau={int(time.time())}" '
        f"-n {CHROME_ACTIVITY}"
    )
    time.sleep(wait)
    codes = re.findall(r"net_error -(\d+)", dev.logcat())
    if codes:
        return False, f"net_error -{codes[0]}"
    return True, ""



def parse_hosts(values: list[str]) -> list[str]:
    hosts: list[str] = []
    for value in values:
        candidate = Path(value)
        if candidate.is_file():
            raw = candidate.read_text(encoding="utf-8")
            entries = [line.strip() for line in raw.splitlines()]
        else:
            entries = [part.strip() for part in value.split(",")]
        for entry in entries:
            if not entry or entry.startswith("#"):
                continue
            host = re.sub(r"^[a-z]+://", "", entry).split("/")[0].split(":")[0]
            if host and host not in hosts:
                hosts.append(host)
    return hosts


# ------------------------------------------------------------------------- rendering


class Paint:
    enabled = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    @classmethod
    def wrap(cls, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if cls.enabled else text

    @classmethod
    def ok(cls, text: str) -> str:
        return cls.wrap(text, "32")

    @classmethod
    def bad(cls, text: str) -> str:
        return cls.wrap(text, "31")

    @classmethod
    def warn(cls, text: str) -> str:
        return cls.wrap(text, "33")

    @classmethod
    def dim(cls, text: str) -> str:
        return cls.wrap(text, "2")


def print_device(dev: Device, store: StoreIndex | None, tracked: dict[str, str]) -> None:
    print(f"device      {dev.model} | Android {dev.android_release} (API {dev.sdk})")
    if store is not None:
        print(f"system CAs  {len(store)} roots")
    else:
        print("system CAs  " + Paint.warn("unavailable (could not read /system/etc/security/cacerts)"))
    print(f"user CAs    {len(tracked)} roots installed by this tool")
    if dev.sdk >= 24:
        print(
            Paint.dim(
                "note        apps targeting API 24+ ignore user CAs; browsers and older apps still benefit"
            )
        )


def cmd_doctor(args) -> int:
    adb = find_adb()
    dev = pick_device(adb, args.serial)
    bundle = fetch_bundle(
        refresh=args.refresh,
        max_age=timedelta(days=args.max_age_days),
        local_path=Path(args.bundle) if args.bundle else None,
    )
    store = load_system_store(dev)
    tracked = tracked_roots(dev.serial)
    hosts = parse_hosts(args.hosts) if args.hosts else list(DEFAULT_HOSTS)

    print_device(dev, store, tracked)
    print(
        f"ca bundle   {len(bundle)} roots | {bundle.origin} | {bundle.age()} "
        f"| sha256 {bundle.sha256[:16]}"
    )
    print()

    results = [analyse_host(host, bundle.certs, store, tracked) for host in hosts]

    if args.browser:
        for result in results:
            if result.source != "missing":
                continue
            trusted, detail = browser_check(dev, result.host, wait=args.wait)
            if trusted is True:
                result.source = "user-untracked"
            elif trusted is False:
                result.error = detail

    width = max(len(host) for host in hosts) + 2
    for result in results:
        if result.source == "system":
            status = Paint.ok("ok")
        elif result.source == "user":
            status = Paint.ok("ok*")
        elif result.source == "user-untracked":
            status = Paint.ok("ok?")
        elif result.source == "missing":
            status = Paint.bad("MISSING")
        else:
            status = Paint.warn(result.source.upper())
        root = result.anchor.common_name if result.anchor else result.error
        print(f"{result.host:<{width}} {status:<16} {root}")

    missing = {result.anchor.fingerprint: result.anchor for result in results if result.source == "missing"}
    print()
    if missing:
        names = ", ".join(sorted(cert.common_name for cert in missing.values()))
        print(f"{len(missing)} root(s) missing: {names}")
        print("run: android-ca-updater fix")
        return 1
    print(Paint.ok("all probed hosts chain to roots this device trusts"))
    if any(result.source == "user" for result in results):
        print(Paint.dim("* trusted through a user CA installed by this tool"))
    if any(result.source == "user-untracked" for result in results):
        print(Paint.dim("? the browser loads it, but the user CA was not installed by this tool"))
    return 0


def cmd_fix(args) -> int:
    adb = find_adb()
    dev = pick_device(adb, args.serial)
    bundle = fetch_bundle(
        refresh=args.refresh,
        max_age=timedelta(days=args.max_age_days),
        local_path=Path(args.bundle) if args.bundle else None,
    )
    store = load_system_store(dev)
    tracked = tracked_roots(dev.serial)

    if args.all_missing:
        targets = {
            cert.fingerprint: cert
            for cert in bundle.certs
            if (store is None or not store.has(cert)) and cert.fingerprint not in tracked
        }
    else:
        hosts = parse_hosts(args.hosts) if args.hosts else list(DEFAULT_HOSTS)
        results = [analyse_host(host, bundle.certs, store, tracked) for host in hosts]
        if args.browser and not dev.is_locked():
            for result in results:
                if result.source != "missing":
                    continue
                trusted, _ = browser_check(dev, result.host, wait=args.wait)
                if trusted is True:
                    result.source = "user-untracked"
        targets = {
            result.anchor.fingerprint: result.anchor
            for result in results
            if result.source == "missing" and result.anchor
        }

    if not targets:
        print(Paint.ok("nothing to install"))
        return 0

    ordered = sorted(targets.values(), key=lambda cert: cert.common_name)
    print(f"{len(ordered)} root(s) to install:")
    for cert in ordered:
        print(f"  - {cert.common_name}  ({Paint.dim(cert.subject)})")
    print()

    if not args.yes and not args.dry_run:
        if not sys.stdin.isatty():
            raise ToolError("refusing to install without confirmation; pass --yes")
        answer = input("install these as user CAs on the device? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            print("aborted")
            return 1

    if args.dry_run:
        print("dry run: no changes made")
        return 0

    dev.ensure_unlocked()
    failures = 0
    for cert in ordered:
        name = safe_cert_name(cert.common_name)
        try:
            install_root(dev, cert, name)
            print(f"  {Paint.ok('installed')} {name}")
        except NeedsUnlock:
            raise
        except ToolError as exc:
            failures += 1
            print(f"  {Paint.bad('failed')}    {name}: {exc}")

    print()
    if failures:
        print(f"{failures} root(s) failed. Run `doctor` for details.")
        return 1
    print(Paint.ok("done") + " - run `android-ca-updater verify` to confirm in the browser")
    return 0


def cmd_verify(args) -> int:
    adb = find_adb()
    dev = pick_device(adb, args.serial)
    hosts = parse_hosts(args.hosts) if args.hosts else list(DEFAULT_HOSTS)

    broken = 0
    for host in hosts:
        trusted, detail = browser_check(dev, host, wait=args.wait)
        if trusted is None:
            print(f"{host:<32} {Paint.warn('skipped')} {detail}")
        elif trusted:
            print(f"{host:<32} {Paint.ok('ok')}")
        else:
            broken += 1
            print(f"{host:<32} {Paint.bad('BROKEN')} {detail}")

    print()
    if broken:
        print(f"{broken} host(s) still fail. Run `doctor` to see which root is missing.")
        return 1
    print(Paint.ok("browser TLS checks passed"))
    return 0


def cmd_list(args) -> int:
    adb = find_adb()
    dev = pick_device(adb, args.serial)
    bundle = fetch_bundle(
        refresh=args.refresh,
        quiet=True,
        max_age=timedelta(days=args.max_age_days),
        local_path=Path(args.bundle) if args.bundle else None,
    )
    store = load_system_store(dev)
    tracked = tracked_roots(dev.serial)

    for cert in sorted(bundle.certs, key=lambda item: item.common_name.lower()):
        if store is not None and store.has(cert):
            state = "system"
        elif cert.fingerprint in tracked:
            state = "user"
        else:
            state = Paint.dim("missing")
        expires = cert.not_after.strftime("%Y-%m-%d")
        print(f"{cert.common_name:<52} {state:<10} expires {expires}")
    return 0


# ------------------------------------------------------------------------------ cli


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="android-ca-updater",
        description="Install modern root CAs on legacy Android devices over adb.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  android-ca-updater doctor\n"
            "  android-ca-updater fix --yes\n"
            "  android-ca-updater doctor --hosts my-sites.txt\n"
            "  android-ca-updater verify\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--serial", help="adb device serial (required if several are connected)")
        sub.add_argument("--refresh", action="store_true", help="re-download the CA bundle")
        sub.add_argument(
            "--max-age-days",
            type=float,
            default=BUNDLE_MAX_AGE.days,
            metavar="N",
            help=f"re-download the CA bundle after N days (default {BUNDLE_MAX_AGE.days})",
        )
        sub.add_argument(
            "--bundle",
            metavar="PATH",
            help="use a local CA bundle file instead of downloading one",
        )
        sub.add_argument(
            "--hosts",
            nargs="+",
            metavar="HOST",
            help="hosts to check: one or more hosts/URLs, or a file with one per line",
        )

    doctor = subparsers.add_parser("doctor", help="report which hosts fail and which root is missing")
    add_common(doctor)
    doctor.add_argument(
        "--browser",
        action="store_true",
        help="confirm hosts that look broken by loading them in Chrome and reading logcat",
    )
    doctor.add_argument("--wait", type=float, default=4.0, help="seconds to wait per browser check")
    doctor.set_defaults(func=cmd_doctor)

    fix = subparsers.add_parser("fix", help="install the missing roots as user CAs")
    add_common(fix)
    fix.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    fix.add_argument("--dry-run", action="store_true", help="show what would be installed")
    fix.add_argument(
        "--browser",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="skip roots for hosts the browser already loads (default: on when unlocked)",
    )
    fix.add_argument("--wait", type=float, default=4.0, help="seconds to wait per browser check")
    fix.add_argument(
        "--all-missing",
        action="store_true",
        help="install every bundle root the device lacks (many taps)",
    )
    fix.set_defaults(func=cmd_fix)

    verify = subparsers.add_parser("verify", help="check hosts in Chrome and read TLS errors from logcat")
    add_common(verify)
    verify.add_argument("--wait", type=float, default=4.0, help="seconds to wait per host (default 4)")
    verify.set_defaults(func=cmd_verify)

    listing = subparsers.add_parser("list", help="list CA bundle roots and their status on the device")
    add_common(listing)
    listing.set_defaults(func=cmd_list)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except NeedsUnlock as exc:
        print(Paint.bad(f"error: {exc}"), file=sys.stderr)
        return 2
    except NeedsScreenLock as exc:
        print(Paint.bad(f"error: {exc}"), file=sys.stderr)
        return 2
    except ToolError as exc:
        print(Paint.bad(f"error: {exc}"), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
