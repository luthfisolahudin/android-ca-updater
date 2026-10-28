"""Mozilla certdata.txt parsing and trust classification."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from .bundle import HttpClient
from .certs import Cert
from .config import BUNDLE_MAX_AGE, CERTDATA_URL, MIN_ROOTS, TRUSTED_FOR_TLS, Paths
from .errors import ToolError
from .process import parse_timestamp, read_json, write_atomic

CERTDATA_HEADER = re.compile(r'^# (Certificate|Trust for Certificate|Trust for) "(.*)"$')
OCTAL_ESCAPE = re.compile(r"\\([0-7]{1,3})")
_SHA1_COMMENT = re.compile(r"# Fingerprint \(SHA1\): (.+)$")
_NOT_AFTER_COMMENT = re.compile(r"# Not Valid After\s*:\s*(.+)$")


@dataclass(frozen=True)
class CertRecord:
    label: str
    server_auth: str | None
    distrust_after: datetime | None
    not_after: datetime | None


class CertdataProvider(Protocol):
    def get(
        self,
        *,
        refresh: bool = ...,
        quiet: bool = ...,
        max_age: timedelta = ...,
    ) -> dict[str, CertRecord]: ...


def certdata_octal(lines: list[str]) -> bytes:
    # Strip the source lines, never the decoded bytes: the payload is binary and
    # a fingerprint may legitimately start or end with a whitespace byte.
    text = "".join(line.strip() for line in lines)
    decoded = OCTAL_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), text)
    return decoded.encode("latin-1")


def certdata_attribute(block: dict[str, Any], name: str) -> str | None:
    lines: list[str] = block["lines"]
    for index, line in enumerate(lines):
        if not line.startswith(name):
            continue
        if "MULTILINE_OCTAL" not in line:
            return line.split()[-1]
        buffer = []
        for follower in lines[index + 1 :]:
            if follower.strip() == "END":
                break
            buffer.append(follower)
        return certdata_octal(buffer).decode("latin-1")
    return None


def certdata_sha1(block: dict[str, Any]) -> str | None:
    for line in block["lines"]:
        match = _SHA1_COMMENT.match(line)
        if match:
            return match.group(1).replace(":", "").lower()
    raw = certdata_attribute(block, "CKA_CERT_SHA1_HASH")
    return raw.encode("latin-1").hex() if raw else None


def parse_certdata_date(raw: str | None) -> datetime | None:
    if not raw or not raw.endswith("Z"):
        return None
    try:
        if len(raw) == 13:
            return datetime.strptime(raw, "%y%m%d%H%M%SZ").replace(tzinfo=UTC)
        if len(raw) == 15:
            return datetime.strptime(raw, "%Y%m%d%H%M%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None
    return None


def parse_not_after(block: dict[str, Any]) -> datetime | None:
    for line in block["lines"]:
        match = _NOT_AFTER_COMMENT.match(line)
        if not match:
            continue
        try:
            return datetime.strptime(
                re.sub(r"\s+", " ", match.group(1).strip()), "%a %b %d %H:%M:%S %Y"
            ).replace(tzinfo=UTC)
        except ValueError:
            return None
    return None


def decode_label(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return chr(int(match.group(1), 16))

    decoded = re.sub(r"\\([0-9A-Fa-f]{2})", replace, value)
    return decoded.encode("latin-1", "replace").decode("utf-8", "replace")


def parse_certdata_records(text: str) -> dict[str, CertRecord]:
    blocks: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        match = CERTDATA_HEADER.match(line)
        if match:
            if current is not None:
                blocks.append(current)
            current = {"kind": match.group(1), "label": decode_label(match.group(2)), "lines": []}
        elif current is not None:
            current["lines"].append(line)
    if current is not None:
        blocks.append(current)

    found: dict[str, dict[str, Any]] = {}
    for block in blocks:
        fingerprint = certdata_sha1(block)
        if not fingerprint:
            continue
        record = found.setdefault(
            fingerprint,
            {
                "label": block["label"],
                "server_auth": None,
                "distrust_after": None,
                "not_after": parse_not_after(block),
            },
        )
        if block["kind"] == "Certificate":
            record["distrust_after"] = parse_certdata_date(
                certdata_attribute(block, "CKA_NSS_SERVER_DISTRUST_AFTER")
            )
        else:
            record["server_auth"] = certdata_attribute(block, "CKA_TRUST_SERVER_AUTH")
    return {key: CertRecord(**value) for key, value in found.items()}


def parse_certdata(text: str) -> dict[str, CertRecord]:
    records = parse_certdata_records(text)
    if len(records) < MIN_ROOTS:
        raise ToolError(f"certdata looks truncated ({len(records)} entries)")
    return records


@dataclass
class CertdataStore:
    """Downloads and caches Mozilla's certdata.txt."""

    paths: Paths
    http: HttpClient
    now: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))

    def get(
        self,
        *,
        refresh: bool = False,
        quiet: bool = False,
        max_age: timedelta = BUNDLE_MAX_AGE,
    ) -> dict[str, CertRecord]:
        meta = read_json(self.paths.certdata_meta) or {}
        cached_at = parse_timestamp(meta.get("fetched_at"))
        is_fresh = cached_at is not None and self.now() - cached_at < max_age

        if refresh or not is_fresh or not self.paths.certdata_txt.exists():
            self._download(meta=meta, quiet=quiet)

        if not self.paths.certdata_txt.exists():
            raise ToolError("cannot obtain Mozilla certdata and no cached copy exists")
        return parse_certdata(self.paths.certdata_txt.read_text(encoding="utf-8", errors="replace"))

    def _download(self, *, meta: dict[str, Any], quiet: bool) -> None:
        try:
            body, headers = self.http.get(
                CERTDATA_URL,
                _optional_string(meta.get("etag")),
                _optional_string(meta.get("last_modified")),
            )
        except (OSError, RuntimeError) as exc:
            if not self.paths.certdata_txt.exists():
                raise ToolError(f"cannot download certdata: {exc}") from exc
            if not quiet:
                print(f"warning: using cached certdata ({exc})", file=sys.stderr)
            return

        if body is None:
            text = self.paths.certdata_txt.read_text(encoding="utf-8", errors="replace")
        else:
            text = body.decode("utf-8", "replace")

        try:
            parse_certdata(text)
        except ToolError as exc:
            if not quiet:
                print(f"warning: rejected certdata download: {exc}", file=sys.stderr)
            return

        if body is not None:
            write_atomic(self.paths.certdata_txt, text)
        fresh = {
            "source": "mozilla-gecko-dev",
            "url": CERTDATA_URL,
            "fetched_at": self.now().isoformat(timespec="seconds"),
            "etag": headers.get("ETag"),
            "last_modified": headers.get("Last-Modified"),
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
        }
        meta.clear()
        meta.update(fresh)
        write_atomic(self.paths.certdata_meta, json.dumps(meta, indent=2))
        if not quiet and body is not None:
            print("Mozilla certdata updated")


def classify_root(cert: Cert, records: dict[str, CertRecord], now: datetime | None = None) -> str:
    current = now or datetime.now(UTC)
    record = records.get(cert.sha1)
    if record is None:
        return "expired" if cert.not_after <= current else "removed"
    if record.server_auth != TRUSTED_FOR_TLS:
        return "distrusted"
    if record.distrust_after is not None and record.distrust_after <= current:
        return "distrusted"
    if cert.not_after <= current:
        return "expired"
    return "fine"


def classify_fingerprint(
    sha1: str, records: dict[str, CertRecord], now: datetime | None = None
) -> str:
    current = now or datetime.now(UTC)
    record = records.get(sha1)
    if record is None:
        return "removed"
    if record.server_auth != TRUSTED_FOR_TLS:
        return "distrusted"
    if record.distrust_after is not None and record.distrust_after <= current:
        return "distrusted"
    if record.not_after is not None and record.not_after <= current:
        return "expired"
    return "fine"


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None
