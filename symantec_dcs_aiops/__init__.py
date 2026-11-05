"""Symantec DCS AIops package."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("symantec-dcs-aiops")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"
