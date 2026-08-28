"""Minimal kopal_registry stub for local dev/tests without installing kopal-registry.

At runtime, Kopal provides the real ``kopal_registry`` package. This stub is
only used when the package is not installed (pytest, validation scripts, etc.).
"""

from __future__ import annotations

import sys
from types import ModuleType
from typing import Any, Callable


def ensure_kopal_registry_stub() -> None:
    if "kopal_registry" in sys.modules:
        return
    try:
        import kopal_registry  # noqa: F401
        return
    except ImportError:
        pass

    class RegistrySecret:
        def __init__(
            self,
            name: str,
            keys: list[str],
            optional_keys: list[str] | None = None,
        ) -> None:
            self.name = name
            self.keys = keys
            self.optional_keys = optional_keys or []

    class _Registry:
        def register(self, **kwargs: Any) -> Callable[[Any], Any]:
            def decorator(fn: Any) -> Any:
                return fn

            return decorator

    secrets_mod = ModuleType("kopal_registry.secrets")
    secrets_mod.get = lambda key: ""  # type: ignore[attr-defined]

    mod = ModuleType("kopal_registry")
    mod.registry = _Registry()
    mod.RegistrySecret = RegistrySecret
    mod.secrets = secrets_mod
    sys.modules["kopal_registry"] = mod
    sys.modules["kopal_registry.secrets"] = secrets_mod
