from __future__ import annotations

from datetime import timedelta

import pytest

from android_ca_updater import cli
from android_ca_updater._version import __version__
from android_ca_updater.certdata import CertRecord
from android_ca_updater.cli import build_parser, main
from android_ca_updater.diagnostics import HostResult
from android_ca_updater.errors import NeedsUnlock, ToolError
from android_ca_updater.truststore import build_index
from fakes import FakeBundles, FakeCertdata, FakeDevice, make_cert, make_context

ANCHOR = make_cert(subject="CN=Anchor Root")


@pytest.fixture(autouse=True)
def stub_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "require_openssl", lambda: "openssl")


@pytest.fixture(autouse=True)
def no_browser_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "browser_check", lambda device, host, wait=4.0: (False, ""))


def analyse_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli,
        "analyse_host",
        lambda host, bundle, store, tracked: HostResult(host, ANCHOR, "missing"),
    )


def analyse_source(monkeypatch: pytest.MonkeyPatch, source: str) -> None:
    monkeypatch.setattr(
        cli,
        "analyse_host",
        lambda host, bundle, store, tracked: HostResult(host, None, source),
    )


def test_parser_knows_every_command() -> None:
    parser = build_parser()
    for command in ("doctor", "fix", "verify", "audit", "revoke", "list"):
        assert parser.parse_args([command]).command == command


def test_version_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out


@pytest.mark.parametrize("argv", [[], ["nope"]])
def test_bad_usage_exits_two(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(argv)
    assert excinfo.value.code == 2


def test_doctor_reports_missing_roots(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ctx = make_context(paths=paths, device=FakeDevice(), bundles=FakeBundles([ANCHOR]))
    analyse_missing(monkeypatch)
    monkeypatch.setattr(cli, "load_system_store", lambda *args: None)

    assert main(["doctor", "--hosts", "github.com"], ctx=ctx) == 1

    out = capsys.readouterr().out
    assert "github.com" in out
    assert "1 root(s) missing: Anchor Root" in out
    assert "run: android-ca-updater fix" in out


def test_doctor_success(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ctx = make_context(paths=paths, device=FakeDevice(), bundles=FakeBundles([ANCHOR]))
    analyse_source(monkeypatch, "system")
    monkeypatch.setattr(cli, "load_system_store", lambda *args: None)

    assert main(["doctor", "--hosts", "github.com"], ctx=ctx) == 0

    assert "all probed hosts chain to roots this device trusts" in capsys.readouterr().out


def test_doctor_passes_bundle_options(paths, monkeypatch: pytest.MonkeyPatch) -> None:
    bundles = FakeBundles([ANCHOR])
    ctx = make_context(paths=paths, device=FakeDevice(), bundles=bundles)
    analyse_source(monkeypatch, "system")
    monkeypatch.setattr(cli, "load_system_store", lambda *args: None)

    main(["doctor", "--hosts", "github.com", "--max-age-days", "7"], ctx=ctx)

    assert bundles.calls[0]["max_age"] == timedelta(days=7)


def test_doctor_browser_check_marks_untracked_roots(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ctx = make_context(paths=paths, device=FakeDevice(), bundles=FakeBundles([ANCHOR]))
    analyse_missing(monkeypatch)
    monkeypatch.setattr(cli, "load_system_store", lambda *args: None)
    monkeypatch.setattr(cli, "browser_check", lambda device, host, wait=4.0: (True, ""))

    assert main(["doctor", "--browser", "--hosts", "github.com"], ctx=ctx) == 0

    out = capsys.readouterr().out
    assert "ok?" in out
    assert "was not installed by this tool" in out


def test_doctor_rejects_invalid_hosts(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ctx = make_context(paths=paths, device=FakeDevice())
    monkeypatch.setattr(cli, "load_system_store", lambda *args: None)

    assert main(["doctor", "--hosts", "foo;bar"], ctx=ctx) == 2
    assert "invalid host" in capsys.readouterr().err


def test_fix_dry_run_installs_nothing(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    device = FakeDevice()
    ctx = make_context(paths=paths, device=device, bundles=FakeBundles([ANCHOR]))
    analyse_missing(monkeypatch)
    monkeypatch.setattr(cli, "load_system_store", lambda *args: None)

    assert main(["fix", "--dry-run", "--hosts", "github.com"], ctx=ctx) == 0

    out = capsys.readouterr().out
    assert "1 root(s) to install:" in out
    assert "Anchor Root" in out
    assert "dry run: no changes made" in out
    assert device.taps == []
    assert device.pushes == []


def test_fix_requires_confirmation(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ctx = make_context(paths=paths, device=FakeDevice(), bundles=FakeBundles([ANCHOR]))
    analyse_missing(monkeypatch)
    monkeypatch.setattr(cli, "load_system_store", lambda *args: None)
    monkeypatch.setattr(cli.sys, "stdin", _NonInteractive())

    assert main(["fix", "--hosts", "github.com"], ctx=ctx) == 2
    assert "pass --yes" in capsys.readouterr().err


def test_fix_installs_each_missing_root(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    installed: list[str] = []
    ctx = make_context(paths=paths, device=FakeDevice(), bundles=FakeBundles([ANCHOR]))
    analyse_missing(monkeypatch)
    monkeypatch.setattr(cli, "load_system_store", lambda *args: None)
    monkeypatch.setattr(
        cli, "install_root", lambda device, cert, name, store: installed.append(name)
    )

    assert main(["fix", "--yes", "--hosts", "github.com"], ctx=ctx) == 0

    assert installed == ["Anchor Root"]
    assert "installed" in capsys.readouterr().out


def test_fix_refuses_distrusted_roots(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    record = CertRecord(
        label="Anchor", server_auth="CKT_NSS_NOT_TRUSTED", distrust_after=None, not_after=None
    )
    ctx = make_context(
        paths=paths,
        device=FakeDevice(),
        bundles=FakeBundles([ANCHOR]),
        certdata=FakeCertdata({ANCHOR.sha1: record}),
    )
    analyse_missing(monkeypatch)
    monkeypatch.setattr(cli, "load_system_store", lambda *args: None)

    assert main(["fix", "--dry-run", "--hosts", "github.com"], ctx=ctx) == 1
    assert "refusing to install distrusted root(s)" in capsys.readouterr().out


def test_fix_reports_nothing_to_do(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ctx = make_context(paths=paths, device=FakeDevice(), bundles=FakeBundles([ANCHOR]))
    analyse_source(monkeypatch, "system")
    monkeypatch.setattr(cli, "load_system_store", lambda *args: None)

    assert main(["fix", "--dry-run", "--hosts", "github.com"], ctx=ctx) == 0
    assert "nothing to install" in capsys.readouterr().out


def test_verify_reports_broken_hosts(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ctx = make_context(paths=paths, device=FakeDevice())
    monkeypatch.setattr(
        cli, "browser_check", lambda device, host, wait=4.0: (False, "net_error -202")
    )

    assert main(["verify", "--hosts", "github.com"], ctx=ctx) == 1
    out = capsys.readouterr().out
    assert "BROKEN" in out
    assert "net_error -202" in out


def test_verify_skips_without_chrome(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ctx = make_context(paths=paths, device=FakeDevice())
    monkeypatch.setattr(
        cli, "browser_check", lambda device, host, wait=4.0: (None, "chrome not installed")
    )

    assert main(["verify", "--hosts", "github.com"], ctx=ctx) == 0
    assert "skipped" in capsys.readouterr().out


def test_verify_success(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ctx = make_context(paths=paths, device=FakeDevice())
    monkeypatch.setattr(cli, "browser_check", lambda device, host, wait=4.0: (True, ""))

    assert main(["verify", "--hosts", "github.com"], ctx=ctx) == 0
    assert "browser TLS checks passed" in capsys.readouterr().out


def test_audit_reports_removed_roots(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cert = make_cert(der=b"old-cert", subject="CN=Old Root")
    ctx = make_context(paths=paths, device=FakeDevice(), certdata=FakeCertdata({}))
    monkeypatch.setattr(cli, "load_system_store", lambda *args: build_index([cert]))

    assert main(["audit"], ctx=ctx) == 0

    out = capsys.readouterr().out
    assert "1 removed" in out
    assert "Old Root" in out


def test_audit_reports_a_missing_store(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ctx = make_context(paths=paths, device=FakeDevice(), certdata=FakeCertdata({}))
    monkeypatch.setattr(cli, "load_system_store", lambda *args: None)

    assert main(["audit"], ctx=ctx) == 1
    assert "cannot read the system trust store" in capsys.readouterr().out


def test_audit_flags_stale_user_cas(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cert = make_cert(der=b"user-cert", subject="CN=User Root")
    ctx = make_context(paths=paths, device=FakeDevice(), certdata=FakeCertdata({}))
    ctx.state.track("FAKE123", cert, "User Root")
    monkeypatch.setattr(cli, "load_system_store", lambda *args: build_index([]))

    assert main(["audit"], ctx=ctx) == 0
    out = capsys.readouterr().out
    assert "User Root" in out
    assert "revoke --stale" in out


def test_revoke_dry_run(paths, capsys: pytest.CaptureFixture[str]) -> None:
    cert = make_cert(der=b"user-cert", subject="CN=My Root")
    ctx = make_context(paths=paths, device=FakeDevice(), bundles=FakeBundles([cert]))
    ctx.state.track("FAKE123", cert, "My Root")

    assert main(["revoke", "--name", "My", "--dry-run"], ctx=ctx) == 0

    out = capsys.readouterr().out
    assert "My Root" in out
    assert "dry run: no changes made" in out


def test_revoke_stale_selection(paths, capsys: pytest.CaptureFixture[str]) -> None:
    cert = make_cert(der=b"user-cert", subject="CN=User Root")
    ctx = make_context(paths=paths, device=FakeDevice(), certdata=FakeCertdata({}))
    ctx.state.track("FAKE123", cert, "User Root")

    assert main(["revoke", "--stale", "--dry-run"], ctx=ctx) == 0
    assert "1 user CA(s) to remove" in capsys.readouterr().out


def test_revoke_requires_a_selector(paths, capsys: pytest.CaptureFixture[str]) -> None:
    cert = make_cert(der=b"user-cert", subject="CN=User Root")
    ctx = make_context(paths=paths, device=FakeDevice())
    ctx.state.track("FAKE123", cert, "User Root")

    assert main(["revoke"], ctx=ctx) == 2
    assert "pass --name TEXT or --stale" in capsys.readouterr().err


def test_revoke_with_nothing_installed(paths, capsys: pytest.CaptureFixture[str]) -> None:
    ctx = make_context(paths=paths, device=FakeDevice())
    assert main(["revoke", "--stale"], ctx=ctx) == 0
    assert "nothing installed by this tool" in capsys.readouterr().out


def test_revoke_removes_and_untracks(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cert = make_cert(der=b"user-cert", subject="CN=User Root")
    ctx = make_context(paths=paths, device=FakeDevice(), certdata=FakeCertdata({}))
    ctx.state.track("FAKE123", cert, "User Root")
    removed: list[str] = []
    monkeypatch.setattr(cli, "remove_user_ca", lambda device, name: removed.append(name))

    assert main(["revoke", "--stale", "--yes"], ctx=ctx) == 0

    assert removed == ["User Root"]
    assert ctx.state.tracked("FAKE123") == {}
    assert "removed" in capsys.readouterr().out


def test_list_marks_system_and_missing_roots(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    system = make_cert(der=b"system", subject="CN=System Root")
    missing = make_cert(der=b"missing", subject="CN=Missing Root")
    ctx = make_context(paths=paths, device=FakeDevice(), bundles=FakeBundles([system, missing]))
    monkeypatch.setattr(cli, "load_system_store", lambda *args: build_index([system]))

    assert main(["list"], ctx=ctx) == 0

    out = capsys.readouterr().out
    assert "System Root" in out
    assert "system" in out
    assert "Missing Root" in out
    assert "missing" in out


def test_fix_aborts_when_the_device_locks(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ctx = make_context(paths=paths, device=FakeDevice(), bundles=FakeBundles([ANCHOR]))
    analyse_missing(monkeypatch)
    monkeypatch.setattr(cli, "load_system_store", lambda *args: None)

    def locked(*args: object) -> None:
        raise NeedsUnlock("device is locked - unlock the screen and try again")

    monkeypatch.setattr(cli, "install_root", locked)

    assert main(["fix", "--yes", "--hosts", "github.com"], ctx=ctx) == 2
    assert "device is locked" in capsys.readouterr().err


def test_revoke_aborts_when_the_device_locks(
    paths, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cert = make_cert(der=b"user-cert", subject="CN=User Root")
    ctx = make_context(paths=paths, device=FakeDevice(), certdata=FakeCertdata({}))
    ctx.state.track("FAKE123", cert, "User Root")

    def locked(*args: object) -> None:
        raise NeedsUnlock("device is locked - unlock the screen and try again")

    monkeypatch.setattr(cli, "remove_user_ca", locked)

    assert main(["revoke", "--stale", "--yes"], ctx=ctx) == 2
    assert "device is locked" in capsys.readouterr().err


def test_tool_errors_exit_two(paths, capsys: pytest.CaptureFixture[str]) -> None:
    ctx = make_context(paths=paths, device=FakeDevice())

    def boom(serial: str | None) -> None:
        raise ToolError("no device found")

    ctx.device_factory = boom

    assert main(["doctor"], ctx=ctx) == 2
    assert "error: no device found" in capsys.readouterr().err


def test_keyboard_interrupt_exits_130(paths, capsys: pytest.CaptureFixture[str]) -> None:
    ctx = make_context(paths=paths, device=FakeDevice())

    def boom(serial: str | None) -> None:
        raise KeyboardInterrupt

    ctx.device_factory = boom

    assert main(["doctor"], ctx=ctx) == 130
    assert "aborted" in capsys.readouterr().err


class _NonInteractive:
    def isatty(self) -> bool:
        return False
