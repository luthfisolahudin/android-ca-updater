"""User-facing error types."""

from __future__ import annotations


class ToolError(RuntimeError):
    """A recoverable failure reported to the user as `error: ...`."""


class NeedsUnlock(ToolError):
    """The device screen is locked."""


class NeedsScreenLock(ToolError):
    """Android requires a screen lock before user CAs can be installed."""
