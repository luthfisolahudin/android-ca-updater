from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest

from android_ca_updater.certdata import (
    TRUSTED_FOR_TLS,
    CertdataStore,
    CertRecord,
    classify_fingerprint,
    classify_root,
    decode_label,
    parse_certdata,
    parse_certdata_records,
)
from android_ca_updater.config import CERTDATA_URL, Paths
from android_ca_updater.errors import ToolError
from fakes import NOW, FakeHttp, make_cert


def octal(value: bytes) -> str:
    return "\n".join(
        "".join(f"\\{byte:03o}" for byte in value[index : index + 16])
        for index in range(0, len(value), 16)
    )


def fingerprint_comment(sha1: str) -> str:
    return ":".join(sha1[index : index + 2] for index in range(0, 40, 2)).upper()


CERTDATA_SAMPLE = f"""# Certificate "Test Trusted Root"
# Not Valid After : Mon Nov 10 00:00:00 2031
# Fingerprint (SHA1): AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA
CKA_NSS_SERVER_DISTRUST_AFTER MULTILINE_OCTAL
{octal(b"241130235959Z")}
END

# Trust for "Test Trusted Root"
CKA_CERT_SHA1_HASH MULTILINE_OCTAL
{octal(bytes.fromhex("aa" * 20))}
END
CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR

# Certificate "Test Distrusted Root"
# Not Valid After : Mon Nov 10 00:00:00 2031
# Fingerprint (SHA1): BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB

# Trust for "Test Distrusted Root"
CKA_CERT_SHA1_HASH MULTILINE_OCTAL
{octal(bytes.fromhex("bb" * 20))}
END
CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_NOT_TRUSTED
"""


def synthetic_certdata(count: int) -> str:
    blocks = []
    for index in range(count):
        sha1 = f"{index:040x}"
        blocks.append(
            f'# Certificate "Root {index}"\n'
            "# Not Valid After : Mon Nov 10 00:00:00 2031\n"
            f"# Fingerprint (SHA1): {fingerprint_comment(sha1)}\n"
            f'# Trust for "Root {index}"\n'
            "CKA_CERT_SHA1_HASH MULTILINE_OCTAL\n"
            f"{octal(bytes.fromhex(sha1))}\n"
            "END\n"
            "CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR\n"
        )
    return "\n".join(blocks)


@pytest.fixture
def records() -> dict[str, CertRecord]:
    return parse_certdata_records(CERTDATA_SAMPLE)


def test_parses_both_entries(records: dict[str, CertRecord]) -> None:
    assert len(records) == 2


def test_reads_trust_bits(records: dict[str, CertRecord]) -> None:
    assert records["aa" * 20].server_auth == TRUSTED_FOR_TLS
    assert records["bb" * 20].server_auth == "CKT_NSS_NOT_TRUSTED"


def test_reads_distrust_date(records: dict[str, CertRecord]) -> None:
    assert records["aa" * 20].distrust_after == datetime(2024, 11, 30, 23, 59, 59, tzinfo=UTC)


def test_reads_validity(records: dict[str, CertRecord]) -> None:
    assert records["aa" * 20].not_after is not None
    assert records["aa" * 20].not_after.year == 2031


def test_truncated_certdata_is_rejected() -> None:
    with pytest.raises(ToolError, match="truncated"):
        parse_certdata(CERTDATA_SAMPLE)


def test_synthetic_certdata_is_accepted() -> None:
    assert len(parse_certdata(synthetic_certdata(60))) == 60


def test_decode_label_handles_hex_escapes() -> None:
    assert decode_label(r"Autorit\C3\A9") == "Autorité"


def test_classifies_missing_fingerprint_as_removed(records: dict[str, CertRecord]) -> None:
    assert classify_fingerprint("cc" * 20, records) == "removed"


def test_classifies_not_trusted_as_distrusted(records: dict[str, CertRecord]) -> None:
    assert classify_fingerprint("bb" * 20, records) == "distrusted"


def test_classifies_passed_distrust_date_as_distrusted(records: dict[str, CertRecord]) -> None:
    assert classify_fingerprint("aa" * 20, records) == "distrusted"


def test_classifies_trusted_without_distrust_as_fine() -> None:
    sha1 = "aa" * 20
    record = CertRecord(
        label="ok", server_auth=TRUSTED_FOR_TLS, distrust_after=None, not_after=None
    )
    assert classify_fingerprint(sha1, {sha1: record}) == "fine"


def test_classifies_trusted_expired_as_expired() -> None:
    sha1 = "aa" * 20
    record = CertRecord(
        label="old",
        server_auth=TRUSTED_FOR_TLS,
        distrust_after=None,
        not_after=datetime(2001, 1, 1, tzinfo=UTC),
    )
    assert classify_fingerprint(sha1, {sha1: record}) == "expired"


def test_classify_root_matches_by_der_sha1() -> None:
    der = b"payload"
    digest = hashlib.sha1(der).hexdigest()
    cert = make_cert(der=der)
    records = {
        digest: CertRecord(
            label="x", server_auth=TRUSTED_FOR_TLS, distrust_after=None, not_after=None
        )
    }
    assert classify_root(cert, records) == "fine"


def test_classify_root_marks_unknown_cert_as_removed() -> None:
    assert classify_root(make_cert(der=b"unknown"), {}) == "removed"


def write_cache(paths: Paths, text: str, *, fetched_at: datetime) -> None:
    paths.cache.mkdir(parents=True, exist_ok=True)
    paths.certdata_txt.write_text(text)
    paths.certdata_meta.write_text(json.dumps({"fetched_at": fetched_at.isoformat()}))


def test_fresh_certdata_cache_skips_the_network(paths: Paths) -> None:
    write_cache(paths, synthetic_certdata(50), fetched_at=NOW)
    http = FakeHttp()
    store = CertdataStore(paths, http, now=lambda: NOW)

    assert len(store.get()) == 50
    assert http.calls == []


def test_stale_certdata_is_downloaded(paths: Paths) -> None:
    write_cache(paths, synthetic_certdata(50), fetched_at=NOW.replace(year=2025))
    body = synthetic_certdata(60).encode()
    http = FakeHttp({CERTDATA_URL: (body, {})})
    store = CertdataStore(paths, http, now=lambda: NOW)

    assert len(store.get()) == 60
    assert paths.certdata_txt.read_text() == body.decode()


def test_truncated_download_keeps_the_cached_copy(
    paths: Paths, capsys: pytest.CaptureFixture[str]
) -> None:
    write_cache(paths, synthetic_certdata(50), fetched_at=NOW.replace(year=2025))
    http = FakeHttp({CERTDATA_URL: (b'# Certificate "one"\n', {})})
    store = CertdataStore(paths, http, now=lambda: NOW)

    assert len(store.get(refresh=True)) == 50
    assert "rejected certdata download" in capsys.readouterr().err


def test_missing_certdata_and_no_cache_is_an_error(paths: Paths) -> None:
    store = CertdataStore(paths, FakeHttp({}), now=lambda: NOW)
    with pytest.raises(ToolError, match="cannot download certdata"):
        store.get(quiet=True)
