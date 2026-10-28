# android-ca-updater

Install modern root CAs on legacy Android devices over adb — no root required.

Old Android releases ship a frozen system trust store. Android 6.0.1 (2015) and
earlier have **no CA update mechanism at all**, so every site that chains to a
root issued after that ROM was built fails with `NET::ERR_CERT_AUTHORITY_INVALID`.
In practice that means most of today's web: Let's Encrypt, Google Trust Services,
Amazon, and the newer Sectigo/GlobalSign hierarchies.

This tool finds exactly which roots are missing, downloads the current Mozilla
CA bundle, and installs the missing ones as user CAs by driving Android's own
certificate installer through `uiautomator` — no root, no custom ROM, no
`/system` remount.

## Why not just "install the CA bundle"?

Because Android installs user CAs one at a time through a system dialog, and a
phone only needs a handful. Installing all ~120 roots would mean ~120 dialogs.
`android-ca-updater` verifies real TLS chains, so it only touches what your
device actually needs — usually one to three roots.

## How it works

1. **Reads the device trust store.** Pulls `/system/etc/security/cacerts` and
   indexes every root by public key.
2. **Verifies real chains.** For each host, fetches the served certificate chain
   with `openssl s_client` and checks it against the device store, exactly like
   the browser does.
3. **Finds the anchor.** If the chain fails, resolves which root from the
   [Mozilla CA bundle](https://curl.se/ca/cacert.pem) would fix it.
4. **Installs it.** Converts the root to DER, pushes it to the device, opens
   `com.android.certinstaller`, and taps through the dialog via
   `adb shell input` with UI bounds read from `uiautomator dump`.

Nothing outside the Mozilla/CCADB bundle is ever installable — the tool will not
add arbitrary or self-signed certificates.

## Where the CAs come from

The bundle is *Mozilla's* trust store, not a list maintained by this project:

| Order | Source | What it is |
| --- | --- | --- |
| 1 | `https://curl.se/ca/cacert.pem` | Mozilla NSS `certdata.txt`, published by the curl project |
| 2 | `https://raw.githubusercontent.com/certifi/python-certifi/master/certifi/cacert.pem` | The same Mozilla data, published by python-certifi |

Guarantees enforced in code:

- **HTTPS only, hostname allowlisted.** `assert_trusted_url()` rejects any
  other scheme or host, so a tampered `CA_SOURCES` entry cannot downgrade to
  plain HTTP or an arbitrary mirror.
- **Every download is validated before use.** A bundle is rejected unless it
  contains at least 50 roots, every entry is a self-signed root (subject ==
  issuer), there are no duplicates, and no root is expired. A rejected bundle
  never replaces the last valid cached copy.
- **Only self-signed roots can be installed.** `install_root()` refuses
  anything else, even if it somehow reached the bundle.
- **Fresh by default.** The cache lives for 24 hours, is refreshed with a
  conditional `GET` (`ETag` / `If-Modified-Since`), and `--refresh` forces a
  re-download. `--max-age-days N` changes the window.
- **Provenance is recorded and shown.** `~/.cache/android-ca-updater/cacert.json`
  stores source, URL, fetch time, `ETag` and the SHA-256 of the exact bytes
  used; `doctor` prints them:

  ```
  ca bundle   118 roots | curl.se | 0d old | sha256 796f1389bfea13c0
  ```

- **Offline / pinned bundles.** `--bundle ./cacert.pem` skips the download and
  validates the local file with the same rules — useful for reproducible runs
  or air-gapped machines.

The tool never edits `/system`. Roots are installed as *user* CAs through the
platform installer, so they are always removable from Settings.

## Requirements

- `python3` (3.9+), no third-party packages
- `openssl` in `PATH`
- `adb` in `PATH` (or `adb` from the Android SDK at the usual locations, or `$ADB`)
- a device with USB debugging enabled and a screen lock set (Android requires
  one before user CAs can be installed)

## Install

```bash
git clone https://github.com/luthfisolahudin/android-ca-updater.git
cd android-ca-updater

# run it directly
./android_ca_updater.py doctor

# or install the `android-ca-updater` command
pipx install .
```

## Usage

```bash
android-ca-updater doctor                 # what is broken, and which root fixes it
android-ca-updater doctor --browser       # also confirm in Chrome via logcat
android-ca-updater fix                    # install the missing roots
android-ca-updater fix --dry-run          # show what would be installed
android-ca-updater verify                 # re-check hosts in Chrome
android-ca-updater list                   # every bundle root and its status
```

Bundle options (available on every command):

```bash
android-ca-updater doctor --refresh            # force a fresh download
android-ca-updater doctor --max-age-days 7     # accept a cache up to 7 days old
android-ca-updater doctor --bundle ./ca.pem    # validate and use a local bundle
```

Point it at your own hosts:

```bash
android-ca-updater doctor --hosts github.com,raw.githubusercontent.com,pypi.org
android-ca-updater doctor --hosts hosts.txt      # one host or URL per line
```

Sample output on an Android 6.0.1 device:

```
device      vivo 1606 | Android 6.0.1 (API 23)
system CAs  158 roots
user CAs    0 roots installed by this tool
ca bundle   118 roots | 0d old

github.com                  ok
raw.githubusercontent.com   MISSING          ISRG Root X1
f-droid.org                 MISSING          ISRG Root X1
x.com                       MISSING          ISRG Root X1
notion.so                   ok

1 root(s) missing: ISRG Root X1
run: android-ca-updater fix
```

## What this does not do

- **It does not modify the system store.** User CAs live in the user trust store,
  so they are removable from Settings at any time.
- **It does not make every app work.** Since Android 7 (API 24), apps that target
  API 24+ ignore user CAs unless their network security config opts in. Browsers
  and apps built against older APIs (including most apps that can still run on
  Android 6) do honor them. Certificate-pinned apps ignore them too.
- **It does not survive a factory reset.** Re-run `fix` afterwards.
- `verify` reads `net_error -202` (`ERR_CERT_AUTHORITY_INVALID`) from `logcat`
  after loading each host in Chrome; it is a heuristic, not a formal proof.

## Notes and limitations

- Chrome on Android 6 tops out at version 106 and Play Store no longer ships
  newer WebView builds for it. This tool fixes the trust problem, not the
  end-of-life problem.
- Some vendors store user CAs in a location adb cannot read. Roots installed by
  hand therefore show up as `MISSING` until they are installed through this tool
  (or confirmed with `doctor --browser`, which shows `ok?`).
- Everything the tool installs is recorded in
  `~/.local/state/android-ca-updater/state.json`.
- The CA bundle is cached for 7 days; `--refresh` forces a fresh download.

## Development

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT
