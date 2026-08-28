# AGENTS.md — SOCLib SOAR Integration (Kopal custom actions)

This repo contains **Kopal custom integrations**: Python UDFs and YAML action templates under the `soclib` brand. When editing files here, follow the conventions below and in **`../doc/CONVENTIONS.md`**.

## Setup commands

- Install (dev deps for pytest only; `kopal_registry` is provided by Kopal at runtime):
  ```bash
  pip install -e ".[dev]"
  ```
  or with uv:
  ```bash
  uv sync
  ```
- Validate all action templates before commit:
  ```bash
  uv run tc validate template custom_actions/templates
  ```

## Code style

- **Python:** Import `RegistrySecret`, `registry`, `secrets` from `kopal_registry` (supplied by Kopal at runtime; local tests use `tests/kopal_registry_stub.py`). Use `Annotated` from `typing` and `Doc` from `typing_extensions`.
- **Namespaces:** UDF namespace `integrations.soclib.<integration>`; template namespace `tools.soclib.<integration>`. Template calls UDF via `action: integrations.soclib.<integration>.<action_name>`.
- **Display group:** `"SOCLib / <Tool Name>"` (e.g. `"SOCLib / Active Directory"`).
- **Output:** Every action returns the standard shape `{ success, data, error, meta }`; see `../doc/design/output-standards.md`.
- **Language:** All user-facing strings, comments, and log/error messages in code must be **English** (no Persian/Farsi in code).

## Repository structure

- **Templates:** `custom_actions/templates/tools/soclib/<integration>/<action_name>.yml` — one folder per integration, one YAML per action.
- **Python UDFs:** One module per integration (e.g. `ad_ldap.py`); register with `@registry.register(..., namespace="integrations.soclib.<integration>", secrets=[...])`.
- **Secrets:** Use `RegistrySecret` with fixed names (e.g. `soclib_active_directory`); required and optional keys documented in `../doc/integrations/<integration>/`.

## Testing instructions

- **Before commit** (required when templates or Python changed):
  1. **Docker logs and sync checks** (from workspace root where `doc/` and `scripts/` exist):
     ```powershell
     .\scripts\kopal-sync-debug.ps1
     ```
     This checks API/executor/worker logs, YAML types (including `type: ... | null` → must be `| None`), platform actions, and Python syntax. Fix any reported errors.
  2. **YAML type rules for Kopal:** In `expects` use only `str`, `int`, `bool`, `float`, `list`, `any`, or `str | None` / `int | None` (never `string`, `integer`, `boolean`, or `str | null`). See `../doc/troubleshooting/kopal/03-yaml-type-error.md`.
  3. **Unit tests:**
     ```bash
     uv run pytest tests/test_winrm_output.py tests/test_winrm_templates.py -v
     ```
- Template validation (when `tc` is available): `uv run tc validate template custom_actions/templates`.
- Manual test in Kopal: create the required Secret (see integration docs), add the action to a workflow, run and check output.
- For AD: secret name `soclib_active_directory`; keys and optional keys in `../doc/integrations/soclib-ad/integration-spec-secret.md` and `ssl-validation-requirements.md`.
- For WinRM: secret name `soclib_winrm`; keys and optional keys in `../doc/integrations/soclib-winrm/integration-spec-secret.md`.

## PR / commit

- Run `.\scripts\kopal-sync-debug.ps1` and fix any FAIL (Docker logs, YAML types, Python). Run `uv run pytest tests/test_winrm_output.py tests/test_winrm_templates.py -v`.
- Ensure template validation passes when `tc` is available.
- New actions: add both the YAML under `custom_actions/templates/tools/soclib/<integration>/` and the Python handler with correct namespace and secrets; update docs under `../doc/integrations/` if needed.

## References

- Conventions: `../doc/CONVENTIONS.md`
- AD integration spec and secrets: `../doc/integrations/soclib-ad/integration-spec-secret.md`
- WinRM integration spec and secrets: `../doc/integrations/soclib-winrm/integration-spec-secret.md`
- Output standards: `../doc/design/output-standards.md`
