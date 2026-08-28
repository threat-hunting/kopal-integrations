"""B17 lab smoke action kept for workflow compatibility.

The action is intentionally side-effect free and returns its input message.
"""
from typing import Annotated, Any

from typing_extensions import Doc

from kopal_registry import registry


@registry.register(
    default_title="B17 lab ping",
    description="Minimal lab UDF so B17 workflow registry sync has a deterministic action.",
    display_group="B17 Lab",
    namespace="tools.b17_lab",
    author="Kopal",
)
async def ping(
    message: Annotated[str, Doc("Echo payload.")] = "pong",
) -> dict[str, Any]:
    return {"ok": True, "message": message}
