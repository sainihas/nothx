"""
nothx - Smart enough to say no.

Set it up once. AI handles your inbox forever.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    # Derive the version from installed package metadata so pyproject.toml stays
    # the single source of truth. Hardcoding it here drifted once already: 0.1.10
    # shipped with __version__ frozen at "0.1.9", which made `nothx --version`
    # lie and left `nothx update` permanently offering an upgrade to a version
    # the user already had.
    __version__ = version("nothx")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0+unknown"
