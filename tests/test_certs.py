from __future__ import annotations

from datetime import UTC, datetime

import pytest

from android_ca_updater.certs import Cert, from_json, pem_to_der, to_json
from conftest import FIXTURES, requires_openssl

pytestmark = requires_openssl


def test_pem_to_der_tolerates_trailing_whitespace() -> None:
    text = (FIXTURES / "root-a.pem").read_text() + "\n\n"
    assert pem_to_der(text).startswith(b"0")


def test_pem_to_der_rejects_non_pem() -> None:
    with pytest.raises(ValueError, match="no PEM certificate"):
        pem_to_der("not a certificate")


def test_parse_cert_metadata(root_a: Cert) -> None:
    assert root_a.common_name == "Test Root Alpha"
    assert root_a.subject == root_a.issuer
    assert root_a.not_after.year > 2100
    assert len(root_a.fingerprint) == 64
    assert len(root_a.sha1) == 40
    assert len(root_a.spki_sha256) == 64


def test_common_name_with_escaped_comma() -> None:
    cert = Cert(
        der=b"",
        subject=r"CN=Example\, Inc.,O=Acme,C=ID",
        issuer="",
        not_after=datetime(2100, 1, 1, tzinfo=UTC),
    )
    assert cert.common_name == "Example, Inc."


def test_common_name_falls_back_to_subject() -> None:
    cert = Cert(
        der=b"",
        subject="O=No Common Name",
        issuer="",
        not_after=datetime(2100, 1, 1, tzinfo=UTC),
    )
    assert cert.common_name == "O=No Common Name"


def test_json_roundtrip(root_a: Cert) -> None:
    restored = from_json(to_json(root_a))
    assert restored.der == root_a.der
    assert restored.subject == root_a.subject
    assert restored.issuer == root_a.issuer
    assert restored.not_after == root_a.not_after
    assert restored.spki_sha256 == root_a.spki_sha256


def test_json_roundtrip_uses_cached_spki_without_openssl(root_a: Cert) -> None:
    payload = to_json(root_a)
    payload["spki"] = "deadbeef"
    restored = from_json(payload)
    assert restored.spki_sha256 == "deadbeef"


def test_from_json_rejects_bad_payload() -> None:
    with pytest.raises(TypeError):
        from_json(
            {
                "der": 5,
                "subject": "a",
                "issuer": "b",
                "not_after": "2100-01-01T00:00:00+00:00",
                "spki": None,
            }
        )
    with pytest.raises(KeyError):
        from_json({"der": "AAAA"})
