"""The package imports cleanly and pins the approved Okta JWT library."""

import importlib
import importlib.metadata
import importlib.util

import pytest


@pytest.mark.unit
def test_package_imports_without_side_effects() -> None:
    package = importlib.import_module("identity_lifecycle")

    assert isinstance(package.__version__, str)
    assert package.__version__


@pytest.mark.unit
def test_pyjwt_is_installed_at_the_approved_floor() -> None:
    assert importlib.util.find_spec("jwt") is not None
    assert importlib.util.find_spec("jose") is None

    version = importlib.metadata.version("PyJWT")
    major, minor = (int(part) for part in version.split(".")[:2])
    assert (major, minor) >= (2, 15)
    assert importlib.metadata.packages_distributions()["jwt"] == ["PyJWT"]
