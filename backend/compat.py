"""Compatibility shims for newer Python / setuptools versions.

setuptools 82.0.0 (released February 2026) removed the ``pkg_resources``
module entirely. ``face_recognition_models`` 0.3.0 still does
``from pkg_resources import resource_filename`` at import time, which
breaks ``face_recognition`` on any environment with setuptools >= 82.

This module installs a minimal ``pkg_resources`` shim backed by the
standard-library ``importlib.resources`` module, so face analysis works
without pinning an ancient setuptools.
"""

from __future__ import annotations

import sys
import types


def install_pkg_resources_shim() -> bool:
    """Install a pkg_resources shim if the real module is unavailable.

    Returns True if a shim was installed, False if the real module was
    already importable (nothing to do).
    """
    try:
        import pkg_resources  # noqa: F401
        return False
    except ImportError:
        pass

    from importlib.resources import files

    shim = types.ModuleType("pkg_resources")

    def resource_filename(package_or_requirement, resource_name):
        # Accepts a package name string or a module object, like the
        # original pkg_resources.resource_filename.
        return str(files(package_or_requirement).joinpath(resource_name))

    shim.resource_filename = resource_filename
    sys.modules["pkg_resources"] = shim
    return True
