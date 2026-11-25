# Palate Cleanser

![Palate Cleanser fruit-bowl artwork](docs/assets/Palate-Cleanser.png)

Audit and plan potentially unwanted app cleanup.

The supported Python launcher reads supplied synthetic test inventories and flags items for human review. It does not scan hosts or remove apps. The legacy Windows scanner and remover are archived and disabled in the supported entry points.

## Requirements

- Python 3.11 or newer. Standard library only; no pip packages.
- No administrator privileges, PowerShell, API permissions, Microsoft/Google sign-in or network access needed.
- Only the supplied synthetic JSON fixtures are supported. Do not provide production inventory or private endpoint data.

## Use

From the repository root:

```sh
python3 -B palate_cleanser.py
python3 -B palate_cleanser.py --inventory-stdin < audit-planner/examples/owned-fixture.json
```

The previous launcher filename remains supported for existing automation. The default prints an empty JSON report, not a clean-host result. Explicit stdin mode evaluates only supplied data; output is stdout. Shell redirection reads the selected fixture. The launcher reads its own local Python module, never legacy PowerShell. Reports include proposed human reviews, skipped items, errors and an always-empty `changes` list. Exit 0 can include skips; invalid input/arguments return 2.

## Scope and safety

Only the reserved fake product `org.example.audit-fixture-browser` is modeled. Missing or conflicting ownership, shared roots, unsupported paths and all real products are skipped. Supplied claims are not live-verified evidence. There are no collectors, file removals, registry edits, process termination, service/task changes, uninstallers, elevation or remediation in the active planner.

Old root PowerShell launchers and build entry now fail closed with exit 2. Historical bytes are retained under `legacy/` for review only; **do not execute them**. This intentionally breaks legacy automation rather than silently changing its meaning. Archived code is not sandboxed and remains unsafe if deliberately run. See [migration notes](docs/migration.md).

## Place in the menu

- **Palate Cleanser:** future conservative PUP ownership review, currently synthetic-only.
- **BEC:** phishing investigation.
- **Flapjacks:** tenant-wide configuration/security posture.
- **HashBrown:** evidence tracking.
- **CrumbTrail:** endpoint triage interpretation.

[Response Menu](https://github.com/PendingUpdates/Response-Menu) · [Planner details](audit-planner/README.md) · [Development checks](docs/development.md)

The canonical repository is [PendingUpdates/Palate-Cleanser](https://github.com/PendingUpdates/Palate-Cleanser). The display name is Palate Cleanser. No release-version reset is included. JSON `schema_version: 1` is a schema identifier, not a product release version.

## License

Original software and documentation are provided under the [MIT License](LICENSE). See [license scope](LICENSE-SCOPE.md) for exclusions.
