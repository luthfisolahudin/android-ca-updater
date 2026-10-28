"""Single source of truth for the version reported at runtime."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("android-ca-updater")
except PackageNotFoundError:  # running from a source checkout without an install
    __version__ = "0.0.0+dev"
