"""Validate WinRM YAML templates: structure and UDF action refs."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, ".")

try:
    import yaml
except ImportError:
    yaml = None


TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "custom_actions" / "templates" / "tools" / "soclib" / "winrm"


@pytest.mark.skipif(yaml is None, reason="PyYAML not installed")
def test_winrm_templates_dir_exists():
    assert TEMPLATES_DIR.is_dir(), f"Templates dir not found: {TEMPLATES_DIR}"


def _expected_actions() -> set[str]:
    """Expected UDF action names from winrm.py (Phase 1–3)."""
    return {
        "test_connectivity",
        "run_command",
        "run_script",
        "list_processes",
        "terminate_process",
        "list_connections",
        "list_firewall_rules",
        "delete_firewall_rule",
        "block_ip",
        "add_firewall_rule",
        "list_sessions",
        "logoff_user",
        "shutdown_system",
        "restart_system",
        "get_file",
        "upload_file",
        "copy_file",
        "delete_file",
        "list_applocker_policies",
        "create_applocker_policy",
        "delete_applocker_policy",
        "deactivate_partition",
        "activate_partition",
    }


@pytest.mark.skipif(yaml is None, reason="PyYAML not installed")
@pytest.mark.parametrize("yml_file", sorted(TEMPLATES_DIR.glob("*.yml")), ids=lambda p: p.name)
def test_winrm_template_structure(yml_file: Path):
    """Each YAML has type, definition with title, namespace, name, secrets, steps, returns."""
    raw = yml_file.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    assert data is not None, f"Empty or invalid YAML: {yml_file.name}"
    assert data.get("type") == "action", f"Expected type: action in {yml_file.name}"
    definition = data.get("definition")
    assert definition is not None, f"Missing definition in {yml_file.name}"
    assert "title" in definition, f"Missing definition.title in {yml_file.name}"
    assert "namespace" in definition, f"Missing definition.namespace in {yml_file.name}"
    assert definition.get("namespace") == "tools.soclib.winrm", f"Wrong namespace in {yml_file.name}"
    assert "name" in definition, f"Missing definition.name in {yml_file.name}"
    assert "secrets" in definition, f"Missing definition.secrets in {yml_file.name}"
    steps = definition.get("steps")
    assert steps and len(steps) >= 1, f"Missing or empty steps in {yml_file.name}"
    action_ref = steps[0].get("action")
    assert action_ref is not None, f"Missing step action in {yml_file.name}"
    assert action_ref.startswith("integrations.soclib.winrm."), f"Step action must be integrations.soclib.winrm.* in {yml_file.name}"
    assert "returns" in definition, f"Missing definition.returns in {yml_file.name}"


@pytest.mark.skipif(yaml is None, reason="PyYAML not installed")
def test_winrm_templates_cover_expected_actions():
    """Every expected UDF action has a template with matching name."""
    expected = _expected_actions()
    found = set()
    for yml_file in TEMPLATES_DIR.glob("*.yml"):
        data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
        if data and data.get("type") == "action":
            name = (data.get("definition") or {}).get("name")
            if name:
                found.add(name)
    missing = expected - found
    assert not missing, f"Templates missing for actions: {missing}"
