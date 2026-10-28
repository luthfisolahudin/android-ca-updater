"""Certificate model and PEM/DER parsing.

Everything that needs X.509 metadata shells out to `openssl x509`, keeping the
tool dependency-free.
"""

from __future__ import annotations

import base64
import hashlib
import re
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cached_property
from typing import Any

from .process import run

PEM_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)
_COMMON_NAME = re.compile(r"(?:^|,)CN=((?:\\.|[^,])*)")
_OPENSSL_DATE = "%b %d %H:%M:%S %Y GMT"


@dataclass(frozen=True)
class Cert:
    der: bytes
    subject: str
    issuer: str
    not_after: datetime
    # Persisted so a cached bundle does not need to re-run openssl for SPKI hashes.
    spki_cache: str | None = None

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.der).hexdigest()

    @property
    def sha1(self) -> str:
        return hashlib.sha1(self.der).hexdigest()

    @property
    def pem(self) -> bytes:
        return ssl.DER_cert_to_PEM_cert(self.der).encode()

    @property
    def common_name(self) -> str:
        match = _COMMON_NAME.search(self.subject)
        if not match:
            return self.subject or "unknown"
        return match.group(1).replace("\\,", ",").replace('\\"', '"')

    @cached_property
    def spki_sha256(self) -> str:
        if self.spki_cache is not None:
            return self.spki_cache
        pubkey = run(["openssl", "x509", "-noout", "-pubkey"], data=self.pem).stdout
        spki = run(["openssl", "pkey", "-pubin", "-outform", "DER"], data=pubkey).stdout
        return hashlib.sha256(spki).hexdigest()


def parse_openssl_date(value: str) -> datetime:
    cleaned = re.sub(r"\s+", " ", value.strip())
    return datetime.strptime(cleaned, _OPENSSL_DATE).replace(tzinfo=UTC)


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
    not_after = datetime.now(UTC)
    for line in out.splitlines():
        if line.startswith("subject="):
            subject = line[len("subject=") :].strip()
        elif line.startswith("issuer="):
            issuer = line[len("issuer=") :].strip()
        elif line.startswith("notAfter="):
            not_after = parse_openssl_date(line[len("notAfter=") :])
    return Cert(der=der, subject=subject, issuer=issuer, not_after=not_after)


def to_json(cert: Cert) -> dict[str, Any]:
    return {
        "der": base64.b64encode(cert.der).decode("ascii"),
        "subject": cert.subject,
        "issuer": cert.issuer,
        "not_after": cert.not_after.isoformat(),
        "spki": cert.spki_cache,
    }


def _string_field(payload: Mapping[str, Any], key: str) -> str:
    value = payload[key]
    if not isinstance(value, str):
        raise TypeError(f"field {key!r} is not a string")
    return value


def from_json(payload: Mapping[str, Any]) -> Cert:
    spki = payload.get("spki")
    if spki is not None and not isinstance(spki, str):
        raise TypeError("field 'spki' is not a string")
    return Cert(
        der=base64.b64decode(_string_field(payload, "der")),
        subject=_string_field(payload, "subject"),
        issuer=_string_field(payload, "issuer"),
        not_after=datetime.fromisoformat(_string_field(payload, "not_after")),
        spki_cache=spki,
    )
