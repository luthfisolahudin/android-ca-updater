"""Command-line interface and command orchestration."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ._version import __version__
from .adb import AdbDevice, find_adb, pick_device
from .bundle import Bundle, BundleProvider, BundleStore, UrllibHttpClient
from .certdata import CertdataProvider, CertdataStore, classify_fingerprint, classify_root
from .certs import Cert
from .config import BUNDLE_MAX_AGE, DEFAULT_HOSTS, TRUSTED_FOR_TLS, Paths
from .console import Terminal, print_device
from .credentials import reconcile, remove_user_ca
from .diagnostics import analyse_host, browser_check, parse_hosts
from .errors import NeedsUnlock, ToolError
from .installer import install_root, safe_cert_name
from .process import require_openssl
from .state import StateStore, TrackedRoot
from .truststore import load_system_store


def _opt[T](namespace: argparse.Namespace, name: str, default: T) -> T:
    value = getattr(namespace, name, default)
    if value is None:
        return default
    return value


@dataclass(frozen=True)
class CommonOptions:
    serial: str | None = None
    refresh: bool = False
    max_age_days: float = BUNDLE_MAX_AGE.days
    bundle: str | None = None
    hosts: list[str] | None = None

    @classmethod
    def from_namespace(cls, namespace: argparse.Namespace) -> CommonOptions:
        return cls(
            serial=_opt(namespace, "serial", None),
            refresh=_opt(namespace, "refresh", False),
            max_age_days=_opt(namespace, "max_age_days", float(BUNDLE_MAX_AGE.days)),
            bundle=_opt(namespace, "bundle", None),
            hosts=_opt(namespace, "hosts", None),
        )

    @property
    def max_age(self) -> timedelta:
        return timedelta(days=self.max_age_days)

    def bundle_path(self) -> Path | None:
        return Path(self.bundle) if self.bundle else None


@dataclass(frozen=True)
class DoctorOptions(CommonOptions):
    browser: bool = False
    wait: float = 4.0

    @classmethod
    def from_namespace(cls, namespace: argparse.Namespace) -> DoctorOptions:
        return cls(
            serial=_opt(namespace, "serial", None),
            refresh=_opt(namespace, "refresh", False),
            max_age_days=_opt(namespace, "max_age_days", float(BUNDLE_MAX_AGE.days)),
            bundle=_opt(namespace, "bundle", None),
            hosts=_opt(namespace, "hosts", None),
            browser=_opt(namespace, "browser", False),
            wait=_opt(namespace, "wait", 4.0),
        )


@dataclass(frozen=True)
class FixOptions(CommonOptions):
    yes: bool = False
    dry_run: bool = False
    browser: bool = True
    wait: float = 4.0
    all_missing: bool = False

    @classmethod
    def from_namespace(cls, namespace: argparse.Namespace) -> FixOptions:
        return cls(
            serial=_opt(namespace, "serial", None),
            refresh=_opt(namespace, "refresh", False),
            max_age_days=_opt(namespace, "max_age_days", float(BUNDLE_MAX_AGE.days)),
            bundle=_opt(namespace, "bundle", None),
            hosts=_opt(namespace, "hosts", None),
            yes=_opt(namespace, "yes", False),
            dry_run=_opt(namespace, "dry_run", False),
            browser=_opt(namespace, "browser", True),
            wait=_opt(namespace, "wait", 4.0),
            all_missing=_opt(namespace, "all_missing", False),
        )


@dataclass(frozen=True)
class VerifyOptions(CommonOptions):
    wait: float = 4.0

    @classmethod
    def from_namespace(cls, namespace: argparse.Namespace) -> VerifyOptions:
        return cls(
            serial=_opt(namespace, "serial", None),
            refresh=_opt(namespace, "refresh", False),
            max_age_days=_opt(namespace, "max_age_days", float(BUNDLE_MAX_AGE.days)),
            bundle=_opt(namespace, "bundle", None),
            hosts=_opt(namespace, "hosts", None),
            wait=_opt(namespace, "wait", 4.0),
        )


@dataclass(frozen=True)
class AuditOptions(CommonOptions):
    all_findings: bool = False
    limit: int = 10

    @classmethod
    def from_namespace(cls, namespace: argparse.Namespace) -> AuditOptions:
        return cls(
            serial=_opt(namespace, "serial", None),
            refresh=_opt(namespace, "refresh", False),
            max_age_days=_opt(namespace, "max_age_days", float(BUNDLE_MAX_AGE.days)),
            bundle=_opt(namespace, "bundle", None),
            hosts=_opt(namespace, "hosts", None),
            all_findings=_opt(namespace, "all", False),
            limit=_opt(namespace, "limit", 10),
        )


@dataclass(frozen=True)
class RevokeOptions(CommonOptions):
    name: list[str] | None = None
    stale: bool = False
    yes: bool = False
    dry_run: bool = False

    @classmethod
    def from_namespace(cls, namespace: argparse.Namespace) -> RevokeOptions:
        return cls(
            serial=_opt(namespace, "serial", None),
            refresh=_opt(namespace, "refresh", False),
            max_age_days=_opt(namespace, "max_age_days", float(BUNDLE_MAX_AGE.days)),
            bundle=_opt(namespace, "bundle", None),
            hosts=_opt(namespace, "hosts", None),
            name=_opt(namespace, "name", None),
            stale=_opt(namespace, "stale", False),
            yes=_opt(namespace, "yes", False),
            dry_run=_opt(namespace, "dry_run", False),
        )


@dataclass(frozen=True)
class ListOptions(CommonOptions):
    @classmethod
    def from_namespace(cls, namespace: argparse.Namespace) -> ListOptions:
        return cls(
            serial=_opt(namespace, "serial", None),
            refresh=_opt(namespace, "refresh", False),
            max_age_days=_opt(namespace, "max_age_days", float(BUNDLE_MAX_AGE.days)),
            bundle=_opt(namespace, "bundle", None),
            hosts=_opt(namespace, "hosts", None),
        )


@dataclass
class Context:
    """Everything a command needs, injectable for tests."""

    paths: Paths
    terminal: Terminal
    state: StateStore
    bundles: BundleProvider
    certdata: CertdataProvider
    device_factory: Callable[[str | None], AdbDevice]
    now: Callable[[], datetime]

    @classmethod
    def create(cls) -> Context:
        paths = Paths.from_env()
        http = UrllibHttpClient()
        return cls(
            paths=paths,
            terminal=Terminal(),
            state=StateStore(paths.state),
            bundles=BundleStore(paths, http),
            certdata=CertdataStore(paths, http),
            device_factory=lambda serial: pick_device(find_adb(), serial),
            now=lambda: datetime.now(UTC),
        )


def _bundle(ctx: Context, opts: CommonOptions) -> Bundle:
    return ctx.bundles.get(
        refresh=opts.refresh,
        max_age=opts.max_age,
        local_path=opts.bundle_path(),
    )


def _backfill(ctx: Context, serial: str, tracked: dict[str, TrackedRoot]) -> None:
    if all(info.get("sha1") for info in tracked.values()):
        return
    try:
        certs = ctx.bundles.get(quiet=True).certs
    except ToolError:
        certs = []
    ctx.state.backfill_sha1(serial, tracked, certs)


def command_doctor(ctx: Context, opts: DoctorOptions) -> int:
    device = ctx.device_factory(opts.serial)
    require_openssl()
    bundle = _bundle(ctx, opts)
    store = load_system_store(device, ctx.paths)
    tracked = ctx.state.tracked(device.serial)
    hosts = parse_hosts(opts.hosts) if opts.hosts else list(DEFAULT_HOSTS)

    print_device(ctx.terminal, device, store, len(tracked))
    print(
        f"ca bundle   {len(bundle)} roots | {bundle.origin} | {bundle.age()} "
        f"| sha256 {bundle.sha256[:16]}"
    )
    print()

    results = [analyse_host(host, bundle.certs, store, tracked) for host in hosts]

    if opts.browser:
        for result in results:
            if result.source != "missing":
                continue
            trusted, detail = browser_check(device, result.host, wait=opts.wait)
            if trusted is True:
                result.source = "user-untracked"
            elif trusted is False:
                result.error = detail

    width = max((len(host) for host in hosts), default=0) + 2
    for result in results:
        if result.source == "system":
            status = ctx.terminal.ok("ok")
        elif result.source == "user":
            status = ctx.terminal.ok("ok*")
        elif result.source == "user-untracked":
            status = ctx.terminal.ok("ok?")
        elif result.source == "missing":
            status = ctx.terminal.bad("MISSING")
        else:
            status = ctx.terminal.warn(result.source.upper())
        root = result.anchor.common_name if result.anchor else result.error
        print(f"{result.host:<{width}} {status:<16} {root}")

    missing: dict[str, Cert] = {}
    for result in results:
        if result.source == "missing" and result.anchor is not None:
            missing[result.anchor.fingerprint] = result.anchor
    print()
    if missing:
        names = ", ".join(sorted(cert.common_name for cert in missing.values()))
        print(f"{len(missing)} root(s) missing: {names}")
        print("run: android-ca-updater fix")
        return 1
    print(ctx.terminal.ok("all probed hosts chain to roots this device trusts"))
    if any(result.source == "user" for result in results):
        print(ctx.terminal.dim("* trusted through a user CA installed by this tool"))
    if any(result.source == "user-untracked" for result in results):
        print(
            ctx.terminal.dim(
                "? the browser loads it, but the user CA was not installed by this tool"
            )
        )
    return 0


def command_fix(ctx: Context, opts: FixOptions) -> int:
    device = ctx.device_factory(opts.serial)
    require_openssl()
    bundle = _bundle(ctx, opts)
    store = load_system_store(device, ctx.paths)
    reconcile(device, ctx.state)
    tracked = ctx.state.tracked(device.serial)

    targets: dict[str, Cert] = {}
    if opts.all_missing:
        targets = {
            cert.fingerprint: cert
            for cert in bundle.certs
            if (store is None or not store.has(cert)) and cert.fingerprint not in tracked
        }
    else:
        hosts = parse_hosts(opts.hosts) if opts.hosts else list(DEFAULT_HOSTS)
        results = [analyse_host(host, bundle.certs, store, tracked) for host in hosts]
        if opts.browser and not device.is_locked():
            for result in results:
                if result.source != "missing":
                    continue
                trusted, _ = browser_check(device, result.host, wait=opts.wait)
                if trusted is True:
                    result.source = "user-untracked"
        targets = {}
        for result in results:
            if result.source == "missing" and result.anchor is not None:
                targets[result.anchor.fingerprint] = result.anchor

    if not targets:
        print(ctx.terminal.ok("nothing to install"))
        return 0

    try:
        records = ctx.certdata.get(refresh=opts.refresh, quiet=True, max_age=opts.max_age)
    except ToolError:
        records = {}
    if records:
        blocked = {
            fingerprint: cert
            for fingerprint, cert in targets.items()
            if classify_fingerprint(cert.sha1, records) == "distrusted"
        }
        for fingerprint in blocked:
            targets.pop(fingerprint)
        if blocked:
            names = ", ".join(sorted(cert.common_name for cert in blocked.values()))
            print(ctx.terminal.warn(f"refusing to install distrusted root(s): {names}"))
        if not targets:
            return 1

    ordered = sorted(targets.values(), key=lambda cert: cert.common_name)
    print(f"{len(ordered)} root(s) to install:")
    for cert in ordered:
        print(f"  - {cert.common_name}  ({ctx.terminal.dim(cert.subject)})")
    print()

    if not opts.yes and not opts.dry_run:
        if not sys.stdin.isatty():
            raise ToolError("refusing to install without confirmation; pass --yes")
        answer = input("install these as user CAs on the device? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            print("aborted")
            return 1

    if opts.dry_run:
        print("dry run: no changes made")
        return 0

    device.ensure_unlocked()
    failures = 0
    for cert in ordered:
        name = safe_cert_name(cert.common_name)
        try:
            install_root(device, cert, name, ctx.state)
            print(f"  {ctx.terminal.ok('installed')} {name}")
        except NeedsUnlock:
            raise
        except ToolError as exc:
            failures += 1
            print(f"  {ctx.terminal.bad('failed')}    {name}: {exc}")

    print()
    if failures:
        print(f"{failures} root(s) failed. Run `doctor` for details.")
        return 1
    print(ctx.terminal.ok("done") + " - run `android-ca-updater verify` to confirm in the browser")
    return 0


def command_verify(ctx: Context, opts: VerifyOptions) -> int:
    device = ctx.device_factory(opts.serial)
    hosts = parse_hosts(opts.hosts) if opts.hosts else list(DEFAULT_HOSTS)

    broken = 0
    for host in hosts:
        trusted, detail = browser_check(device, host, wait=opts.wait)
        if trusted is None:
            print(f"{host:<32} {ctx.terminal.warn('skipped')} {detail}")
        elif trusted:
            print(f"{host:<32} {ctx.terminal.ok('ok')}")
        else:
            broken += 1
            print(f"{host:<32} {ctx.terminal.bad('BROKEN')} {detail}")

    print()
    if broken:
        print(f"{broken} host(s) still fail. Run `doctor` to see which root is missing.")
        return 1
    print(ctx.terminal.ok("browser TLS checks passed"))
    return 0


def command_audit(ctx: Context, opts: AuditOptions) -> int:
    device = ctx.device_factory(opts.serial)
    require_openssl()
    store = load_system_store(device, ctx.paths)
    records = ctx.certdata.get(refresh=opts.refresh, max_age=opts.max_age)
    tracked = ctx.state.tracked(device.serial)
    _backfill(ctx, device.serial, tracked)
    now = ctx.now()

    print_device(ctx.terminal, device, store, len(tracked))
    print(f"mozilla     {len(records)} roots in certdata (trust bits + distrust dates)")
    print()

    if store is None:
        print(ctx.terminal.warn("cannot read the system trust store on this device"))
        return 1

    buckets = {"fine": 0, "expired": 0, "distrusted": 0, "removed": 0}
    findings: dict[str, list[tuple[str, str]]] = {"distrusted": [], "removed": [], "expired": []}
    for cert in store.by_fingerprint.values():
        kind = classify_root(cert, records, now)
        buckets[kind] += 1
        if kind == "fine":
            continue
        record = records.get(cert.sha1)
        reason = ""
        if kind == "distrusted" and record is not None:
            if record.distrust_after is not None:
                reason = f"distrust after {record.distrust_after.date()}"
            elif record.server_auth != TRUSTED_FOR_TLS:
                reason = f"server auth {record.server_auth}"
        findings[kind].append((cert.common_name, reason))

    print(
        f"system CAs  {len(store)} roots | {buckets['fine']} fine | "
        f"{buckets['distrusted']} distrusted | {buckets['removed']} removed | "
        f"{buckets['expired']} expired"
    )
    print()

    titles = {
        "distrusted": "not trusted for TLS by Mozilla - highest risk",
        "removed": "no longer in Mozilla's root program",
        "expired": "expired - the certificate itself is inert",
    }
    for kind in ("distrusted", "removed", "expired"):
        items = sorted(findings[kind])
        if not items:
            continue
        print(f"{kind.upper()}  {len(items)} root(s) - {titles[kind]}")
        shown = items if opts.all_findings else items[: opts.limit]
        for name, reason in shown:
            suffix = f"  {ctx.terminal.dim(reason)}" if reason else ""
            print(f"  - {name}{suffix}")
        if not opts.all_findings and len(items) > opts.limit:
            print(ctx.terminal.dim(f"  ... {len(items) - opts.limit} more (use --all)"))
        print()

    stale: list[tuple[str, str]] = []
    for fingerprint, info in tracked.items():
        sha1 = info.get("sha1")
        kind = classify_fingerprint(sha1, records, now) if sha1 else "unknown"
        if kind != "fine":
            stale.append((info.get("name") or fingerprint[:12], kind))
    if tracked:
        print(f"user CAs    {len(tracked)} root(s) installed by this tool")
        for name, kind in sorted(stale):
            print(f"  - {name}  {ctx.terminal.warn(kind)}")
        if stale:
            print("  run: android-ca-updater revoke --stale")
        print()

    if buckets["distrusted"] or buckets["removed"]:
        print(ctx.terminal.warn("system roots cannot be removed from adb on a user build"))
        print(
            ctx.terminal.dim(
                "they live in /system (read-only, dm-verity) and need root to delete or mask"
            )
        )
        print(
            ctx.terminal.dim(
                "options: a rooted device, a maintained custom ROM, or a supported phone"
            )
        )
    return 0


def command_revoke(ctx: Context, opts: RevokeOptions) -> int:
    device = ctx.device_factory(opts.serial)
    tracked = ctx.state.tracked(device.serial)
    if not tracked:
        print("nothing installed by this tool")
        return 0
    _backfill(ctx, device.serial, tracked)

    records = ctx.certdata.get(refresh=opts.refresh, max_age=opts.max_age)
    now = ctx.now()

    targets: list[tuple[str, TrackedRoot]] = []
    if opts.stale:
        for fingerprint, info in tracked.items():
            sha1 = info.get("sha1")
            if sha1 and classify_fingerprint(sha1, records, now) != "fine":
                targets.append((fingerprint, info))
    elif opts.name:
        wanted = [value.lower() for value in opts.name]
        targets = [
            (fingerprint, info)
            for fingerprint, info in tracked.items()
            if any(value in (info.get("name") or "").lower() for value in wanted)
        ]
    else:
        raise ToolError("pass --name TEXT or --stale")

    if not targets:
        print(ctx.terminal.ok("nothing to revoke"))
        return 0

    print(f"{len(targets)} user CA(s) to remove:")
    for _, info in targets:
        print(f"  - {info.get('name')}")
    print()

    if not opts.yes and not opts.dry_run:
        if not sys.stdin.isatty():
            raise ToolError("refusing to remove without confirmation; pass --yes")
        answer = input("remove these user CAs from the device? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            print("aborted")
            return 1

    if opts.dry_run:
        print("dry run: no changes made")
        return 0

    failures = 0
    for fingerprint, info in targets:
        name = info.get("name") or fingerprint[:12]
        try:
            remove_user_ca(device, name)
            ctx.state.untrack(device.serial, fingerprint)
            print(f"  {ctx.terminal.ok('removed')} {name}")
        except NeedsUnlock:
            raise
        except ToolError as exc:
            failures += 1
            print(f"  {ctx.terminal.bad('failed')}  {name}: {exc}")

    print()
    if failures:
        return 1
    print(ctx.terminal.ok("done"))
    return 0


def command_list(ctx: Context, opts: ListOptions) -> int:
    device = ctx.device_factory(opts.serial)
    require_openssl()
    bundle = ctx.bundles.get(
        refresh=opts.refresh,
        quiet=True,
        max_age=opts.max_age,
        local_path=opts.bundle_path(),
    )
    store = load_system_store(device, ctx.paths)
    tracked = ctx.state.tracked(device.serial)

    for cert in sorted(bundle.certs, key=lambda item: item.common_name.lower()):
        if store is not None and store.has(cert):
            state = "system"
        elif cert.fingerprint in tracked:
            state = "user"
        else:
            state = ctx.terminal.dim("missing")
        expires = cert.not_after.strftime("%Y-%m-%d")
        print(f"{cert.common_name:<52} {state:<10} expires {expires}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="android-ca-updater",
        description="Install modern root CAs on legacy Android devices over adb.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  android-ca-updater doctor\n"
            "  android-ca-updater fix --yes\n"
            "  android-ca-updater audit --all\n"
            "  android-ca-updater revoke --stale\n"
            "  android-ca-updater doctor --hosts my-sites.txt\n"
            "  android-ca-updater verify\n"
            "\n"
            "exit codes:\n"
            "  0  success\n"
            "  1  findings reported or some operations failed\n"
            "  2  usage or tool error\n"
            "  130 interrupted\n"
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

    doctor = subparsers.add_parser(
        "doctor", help="report which hosts fail and which root is missing"
    )
    add_common(doctor)
    doctor.add_argument(
        "--browser",
        action="store_true",
        help="confirm hosts that look broken by loading them in Chrome and reading logcat",
    )
    doctor.add_argument("--wait", type=float, default=4.0, help="seconds to wait per browser check")
    doctor.set_defaults(func=command_doctor, options_type=DoctorOptions)

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
    fix.set_defaults(func=command_fix, options_type=FixOptions)

    verify = subparsers.add_parser(
        "verify", help="check hosts in Chrome and read TLS errors from logcat"
    )
    add_common(verify)
    verify.add_argument(
        "--wait", type=float, default=4.0, help="seconds to wait per host (default 4)"
    )
    verify.set_defaults(func=command_verify, options_type=VerifyOptions)

    audit = subparsers.add_parser(
        "audit", help="list expired, distrusted and removed roots in the device trust store"
    )
    add_common(audit)
    audit.add_argument("--all", action="store_true", help="print every finding")
    audit.add_argument("--limit", type=int, default=10, help="findings per category (default 10)")
    audit.set_defaults(func=command_audit, options_type=AuditOptions)

    revoke = subparsers.add_parser("revoke", help="remove user CAs installed by this tool")
    add_common(revoke)
    revoke.add_argument("--name", nargs="+", help="certificate name substring(s) to remove")
    revoke.add_argument(
        "--stale", action="store_true", help="remove roots now distrusted/expired/removed"
    )
    revoke.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    revoke.add_argument("--dry-run", action="store_true", help="show what would be removed")
    revoke.set_defaults(func=command_revoke, options_type=RevokeOptions)

    listing = subparsers.add_parser(
        "list", help="list CA bundle roots and their status on the device"
    )
    add_common(listing)
    listing.set_defaults(func=command_list, options_type=ListOptions)

    return parser


def main(argv: Sequence[str] | None = None, ctx: Context | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    context = ctx or Context.create()
    options = args.options_type.from_namespace(args)
    try:
        return int(args.func(context, options) or 0)
    except ToolError as exc:
        context.terminal.error(str(exc))
        return 2
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        return 130
