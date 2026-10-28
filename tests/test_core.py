import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import android_ca_updater as cli  # noqa: E402

_FIXTURES: dict[str, Path] = {}


def openssl(*args: str) -> None:
    subprocess.run(("openssl", *args), check=True, capture_output=True)


def make_ca(directory: Path, name: str, common_name: str) -> Path:
    key = directory / f"{name}.key"
    cert = directory / f"{name}.pem"
    openssl(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "30",
        "-subj", f"/CN={common_name}",
        "-addext", "basicConstraints=critical,CA:TRUE",
    )
    return cert


def make_leaf(directory: Path, ca_cert: Path, ca_key: Path) -> Path:
    key = directory / "leaf.key"
    csr = directory / "leaf.csr"
    cert = directory / "leaf.pem"
    ext = directory / "leaf.ext"
    ext.write_text("subjectAltName=DNS:leaf.test\n")
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", "/CN=leaf.test")
    openssl(
        "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
        "-CAcreateserial", "-out", str(cert), "-days", "30", "-extfile", str(ext),
    )
    return cert


def setUpModule() -> None:
    directory = Path(tempfile.mkdtemp(prefix="android-ca-updater-tests-"))
    _FIXTURES["dir"] = directory
    _FIXTURES["ca1"] = make_ca(directory, "ca1", "Test Root One")
    _FIXTURES["ca2"] = make_ca(directory, "ca2", "Test Root Two")
    _FIXTURES["leaf"] = make_leaf(directory, _FIXTURES["ca1"], directory / "ca1.key")


class PemParsingTests(unittest.TestCase):
    def test_pem_to_der_tolerates_trailing_whitespace(self) -> None:
        text = _FIXTURES["ca1"].read_text() + "\n\n"
        der = cli.pem_to_der(text)
        self.assertTrue(der.startswith(b"0"))

    def test_pem_to_der_rejects_non_pem(self) -> None:
        with self.assertRaises(ValueError):
            cli.pem_to_der("not a certificate")

    def test_certificate_metadata(self) -> None:
        cert = cli.parse_cert(cli.pem_to_der(_FIXTURES["ca1"].read_text()))
        self.assertEqual(cert.common_name, "Test Root One")
        self.assertEqual(cert.subject, cert.issuer)
        self.assertEqual(len(cert.fingerprint), 64)
        self.assertEqual(len(cert.spki_sha256), 64)

    def test_common_name_with_escaped_comma(self) -> None:
        cert = cli.Cert(der=b"", subject=r'CN=Example\, Inc.,O=Acme,C=ID', issuer="", not_after=cli.datetime.now())
        self.assertEqual(cert.common_name, "Example, Inc.")


class ChainVerificationTests(unittest.TestCase):
    def test_accepts_chain_signed_by_given_anchor(self) -> None:
        leaf = cli.parse_cert(cli.pem_to_der(_FIXTURES["leaf"].read_text()))
        self.assertTrue(cli.verify_chain_with_cafile([leaf], _FIXTURES["ca1"]))

    def test_rejects_chain_signed_by_another_anchor(self) -> None:
        leaf = cli.parse_cert(cli.pem_to_der(_FIXTURES["leaf"].read_text()))
        self.assertFalse(cli.verify_chain_with_cafile([leaf], _FIXTURES["ca2"]))

    def test_missing_anchor_file_is_false(self) -> None:
        leaf = cli.parse_cert(cli.pem_to_der(_FIXTURES["leaf"].read_text()))
        self.assertFalse(cli.verify_chain_with_cafile([leaf], _FIXTURES["dir"] / "nope.pem"))


class HostParsingTests(unittest.TestCase):
    def test_accepts_urls_and_ports(self) -> None:
        hosts = cli.parse_hosts(["https://github.com/foo/bar", "pypi.org:443"])
        self.assertEqual(hosts, ["github.com", "pypi.org"])

    def test_accepts_comma_lists(self) -> None:
        self.assertEqual(cli.parse_hosts(["a.test,b.test"]), ["a.test", "b.test"])

    def test_accepts_file_with_comments(self) -> None:
        path = _FIXTURES["dir"] / "hosts.txt"
        path.write_text("# comment\n\ngithub.com\nhttps://f-droid.org/\n")
        self.assertEqual(cli.parse_hosts([str(path)]), ["github.com", "f-droid.org"])

    def test_deduplicates(self) -> None:
        self.assertEqual(cli.parse_hosts(["a.test,a.test"]), ["a.test"])


class UiParsingTests(unittest.TestCase):
    XML = (
        '<hierarchy><node class="android.widget.LinearLayout" bounds="[0,0][540,960]">'
        '<node class="android.widget.EditText" text="" bounds="[48,405][492,458]"/>'
        '<node class="android.widget.Button" text="Oke" bounds="[48,655][273,712]"/>'
        '<node class="android.widget.Button" text="Batal" bounds="[273,655][492,712]"/>'
        "</node></hierarchy>"
    )

    def setUp(self) -> None:
        self.root = ET.fromstring(self.XML)

    def test_finds_edit_text_center(self) -> None:
        node = cli.find_node(self.root, class_name="EditText")
        self.assertIsNotNone(node)
        self.assertEqual(cli.node_bounds(node), (270, 431))

    def test_finds_ok_button_by_label(self) -> None:
        node = cli.find_node(self.root, class_name="Button", labels=cli.OK_LABELS)
        self.assertEqual(node.get("text"), "Oke")
        self.assertEqual(cli.node_bounds(node), (160, 683))

    def test_unknown_label_returns_none(self) -> None:
        self.assertIsNone(cli.find_node(self.root, class_name="Button", labels=("nope",)))

    def test_malformed_bounds_return_none(self) -> None:
        node = ET.fromstring('<node class="android.widget.Button" bounds="oops"/>')
        self.assertIsNone(cli.node_bounds(node))


class NamingTests(unittest.TestCase):
    def test_strips_unsafe_characters(self) -> None:
        self.assertEqual(cli.safe_cert_name('ISRG Root X1 "test"; rm -rf /'), "ISRG Root X1 test rm -rf")

    def test_removes_shell_metacharacters(self) -> None:
        self.assertNotIn(";", cli.safe_cert_name("a;b"))
        self.assertNotIn('"', cli.safe_cert_name('a"b'))
        self.assertNotIn("$", cli.safe_cert_name("a$b"))

    def test_keeps_fallback_name(self) -> None:
        self.assertEqual(cli.safe_cert_name("***"), "root-ca")


if __name__ == "__main__":
    unittest.main()
