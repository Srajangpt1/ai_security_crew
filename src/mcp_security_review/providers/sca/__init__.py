"""SCA (Software Composition Analysis) providers.

Package registry verification and vulnerability scanning via OSV.dev.
"""

from .osv import OSVScanner
from .registry import PackageRegistry

__all__ = ["OSVScanner", "PackageRegistry"]
