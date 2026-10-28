"""TLS chain fetching and verification through openssl."""

from __future__ import annotations

import os
import ssl
import tempfile
from pathlib import Path

from .certs import PEM_BLOCK, Cert, parse_cert
from .process import run


def fetch_chain(host: str, port: int = 443) -> list[Cert]:
    proc = run(
        ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-showcerts"],
        data=b"",
        timeout=30,
        check=False,
    )
    if not proc.stdout:
        return []
    certs: list[Cert] = []
    for block in PEM_BLOCK.findall(proc.stdout.decode("utf-8", "replace")):
        try:
            certs.append(parse_cert(ssl.PEM_cert_to_DER_cert(block)))
        except (ValueError, RuntimeError):
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
