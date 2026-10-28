"""Mozilla CA bundle acquisition, validation and caching."""

from __future__ import annotations

import hashlib
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from ._version import __version__
from .certs import PEM_BLOCK, Cert, from_json, parse_cert, to_json
from .config import (
    APP_NAME,
    BUNDLE_MAX_AGE,
    MIN_ROOTS,
    PARSED_CACHE_KEEP,
    PARSED_CACHE_MAX_AGE,
    Paths,
)
from .errors import ToolError
from .process import parse_timestamp, read_json, write_atomic

TRUSTED_HOSTS = frozenset({"curl.se", "raw.githubusercontent.com"})


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


class HttpClient(Protocol):
    def get(
        self, url: str, etag: str | None, last_modified: str | None
    ) -> tuple[bytes | None, dict[str, str]]:
        """Fetch `url`, returning `(body, headers)`; body is None on 304."""
        ...


@dataclass(frozen=True)
class UrllibHttpClient:
    """HTTP client that refuses to talk to anything but the allowlisted sources."""

    user_agent: str = f"{APP_NAME}/{__version__}"

    def get(
        self, url: str, etag: str | None, last_modified: str | None
    ) -> tuple[bytes | None, dict[str, str]]:
        assert_trusted_url(url)
        headers = {"User-Agent": self.user_agent}
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


@dataclass
class Bundle:
    certs: list[Cert]
    origin: str
    fetched_at: datetime | None
    sha256: str

    def __len__(self) -> int:
        return len(self.certs)

    def age(self, now: datetime | None = None) -> str:
        if self.fetched_at is None:
            return "unknown"
        current = now or datetime.now(UTC)
        delta = current - self.fetched_at
        if delta < timedelta(hours=1):
            return f"{delta.seconds // 60}m old"
        if delta < timedelta(days=1):
            return f"{delta.seconds // 3600}h old"
        return f"{delta.days}d old"


class BundleProvider(Protocol):
    def get(
        self,
        *,
        refresh: bool = ...,
        quiet: bool = ...,
        max_age: timedelta = ...,
        local_path: Path | None = ...,
    ) -> Bundle: ...


def assert_trusted_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in TRUSTED_HOSTS:
        raise ToolError(f"refusing to download CA bundle from an untrusted URL: {url}")


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
    now = datetime.now(UTC)
    expired = [cert for cert in certs if cert.not_after <= now]
    if expired:
        problems.append(f"{len(expired)} expired root(s)")
    return problems


def prune_parsed_cache(cache: Path, now: datetime | None = None) -> None:
    """Keep the parsed-cert cache bounded."""
    current = now or datetime.now(UTC)
    try:
        files = sorted(
            cache.glob("parsed-*.json"), key=lambda path: path.stat().st_mtime, reverse=True
        )
    except OSError:
        return
    for index, path in enumerate(files):
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, UTC)
        except OSError:
            continue
        if index >= PARSED_CACHE_KEEP or current - mtime > PARSED_CACHE_MAX_AGE:
            path.unlink(missing_ok=True)


def split_bundle(pem_text: str, cache: Path | None = None) -> list[Cert]:
    cache_key = hashlib.sha256(pem_text.encode()).hexdigest()[:16]
    cache_path = cache / f"parsed-{cache_key}.json" if cache is not None else None
    if cache_path is not None and cache_path.exists():
        payload = read_json(cache_path)
        if isinstance(payload, dict):
            items = payload.get("certs")
            if isinstance(items, list) and all(isinstance(item, dict) for item in items):
                try:
                    return [from_json(item) for item in items]
                except (KeyError, TypeError, ValueError):
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

    if cache_path is not None:
        write_atomic(cache_path, json.dumps({"certs": [to_json(cert) for cert in certs]}))
        prune_parsed_cache(cache_path.parent)
    return certs


@dataclass
class BundleStore:
    """Downloads, validates and caches Mozilla's CA bundle."""

    paths: Paths
    http: HttpClient
    now: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))

    def get(
        self,
        *,
        refresh: bool = False,
        quiet: bool = False,
        max_age: timedelta = BUNDLE_MAX_AGE,
        local_path: Path | None = None,
    ) -> Bundle:
        if local_path is not None:
            if not local_path.exists():
                raise ToolError(f"bundle file not found: {local_path}")
            pem_text = local_path.read_text(encoding="utf-8", errors="replace")
            certs = split_bundle(pem_text, self.paths.cache)
            problems = validate_bundle(certs)
            if problems:
                raise ToolError(f"{local_path} is not a usable CA bundle: {', '.join(problems)}")
            return Bundle(
                certs=certs,
                origin=str(local_path),
                fetched_at=datetime.fromtimestamp(local_path.stat().st_mtime, UTC),
                sha256=hashlib.sha256(pem_text.encode()).hexdigest(),
            )

        meta = read_json(self.paths.cacert_meta) or {}
        cached_at = parse_timestamp(meta.get("fetched_at"))
        is_fresh = cached_at is not None and self.now() - cached_at < max_age

        if refresh or not is_fresh or not self.paths.cacert_pem.exists():
            self._download(meta=meta, quiet=quiet)

        if not self.paths.cacert_pem.exists():
            raise ToolError("cannot obtain a CA bundle and no cached copy exists")

        pem_text = self.paths.cacert_pem.read_text(encoding="utf-8", errors="replace")
        certs = split_bundle(pem_text, self.paths.cache)
        return Bundle(
            certs=certs,
            origin=meta.get("source", "cache") if isinstance(meta.get("source"), str) else "cache",
            fetched_at=parse_timestamp(meta.get("fetched_at")),
            sha256=hashlib.sha256(pem_text.encode()).hexdigest(),
        )

    def _download(self, *, meta: dict[str, object], quiet: bool) -> None:
        for source in CA_SOURCES:
            try:
                body, headers = self.http.get(
                    source.url,
                    _optional_string(meta.get("etag")),
                    _optional_string(meta.get("last_modified")),
                )
            except (OSError, urllib.error.URLError) as exc:
                if not quiet:
                    print(f"warning: {source.name} unavailable ({exc})", file=sys.stderr)
                continue
            if body is None:
                meta["fetched_at"] = self.now().isoformat(timespec="seconds")
                write_atomic(self.paths.cacert_meta, json.dumps(meta, indent=2))
                if not quiet:
                    print(f"CA bundle unchanged ({source.name}, not modified)")
                return
            text = body.decode("utf-8", "replace")
            try:
                certs = split_bundle(text, self.paths.cache)
            except ToolError as exc:
                if not quiet:
                    print(f"warning: rejected {source.name} bundle: {exc}", file=sys.stderr)
                continue
            problems = validate_bundle(certs)
            if problems:
                if not quiet:
                    print(
                        f"warning: rejected {source.name} bundle: {', '.join(problems)}",
                        file=sys.stderr,
                    )
                continue
            write_atomic(self.paths.cacert_pem, text)
            fresh = {
                "source": source.name,
                "url": source.url,
                "description": source.description,
                "fetched_at": self.now().isoformat(timespec="seconds"),
                "etag": headers.get("ETag"),
                "last_modified": headers.get("Last-Modified"),
                "sha256": hashlib.sha256(text.encode()).hexdigest(),
            }
            meta.clear()
            meta.update(fresh)
            write_atomic(self.paths.cacert_meta, json.dumps(meta, indent=2))
            if not quiet:
                print(f"CA bundle updated from {source.name}: {len(certs)} roots")
            return


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None
