"""Inert, synthetic-only ownership planner. No operating-system adapter exists.

This is a separate review experiment, not a new PUPRemover release. Supplied
evidence is never described as live verification. A proposal means human review,
and cannot be executed by this module. All real-product rules remain disabled.
"""

import hashlib
import json
import re
import sys


BASELINE_COMMIT = "0c181c54d277dda642be09890ca665b1f77e7d84"
DISPLAY_NAME = "Palate Cleanser"
# Reserved, intentionally synthetic identifiers, not real signatures or hashes.
FIXTURE_PRODUCT = "org.example.audit-fixture-browser"
FIXTURE_PUBLISHER = "Example Synthetic Publisher"
FIXTURE_SIGNER = "a" * 64
FIXTURE_HASH = "b" * 64
FIXTURE_ROOT_SUFFIX = r"\AppData\Local\AuditFixtureBrowser"
FIXTURE_EXECUTABLE = r"\fixture-browser.exe"
MAX_INPUT = 1048576
MAX_RECORDS = 5000


def _report():
    return {
        "schema_version": 1,
        "mode": "Audit",
        "display_name": DISPLAY_NAME,
        "baseline_commit": BASELINE_COMMIT,
        "evidence_scope": "supplied_synthetic_inventory",
        "inventory_sha256": None,
        "proposals": [],
        "skipped": [],
        "changes": [],
        "errors": [],
        "limitations": [
            "No host was scanned; supplied facts are unverified synthetic claims.",
            "No real product rule, collector, mutator, or apply mode exists.",
            "Proposals request human review only and confer no removal authority.",
        ],
    }


def _plain_json(value, depth=0):
    if depth > 12:
        return False
    if type(value) is dict:
        return len(value) <= MAX_RECORDS and all(
            type(k) is str and len(k) <= 100 and _plain_json(v, depth + 1)
            for k, v in value.items()
        )
    if type(value) is list:
        return len(value) <= MAX_RECORDS and all(_plain_json(v, depth + 1) for v in value)
    if type(value) is str:
        return len(value) <= 4096
    return value is None or type(value) in (bool, int)


def _identifier(value):
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", value) is not None


def _canonical_path(value):
    """Compare a narrow literal Windows path grammar; never resolve a real path.

    Reject alternate spellings instead of guessing about devices, ADS, UNC,
    short names, environment expansion, wildcards, dot segments, or Unicode.
    Supplied resolved_path and alias evidence must independently agree too.
    """
    if type(value) is not str or len(value) > 240:
        return None
    if re.fullmatch(r"[A-Za-z]:\\[A-Za-z0-9 _().\\-]+", value) is None:
        return None
    components = value[3:].split("\\")
    for component in components:
        if not component or component in (".", "..") or component.endswith((".", " ")):
            return None
        if component.startswith(" "):
            return None
        stem = component.split(".")[0].lower()
        if stem in ("con", "prn", "aux", "nul") or re.fullmatch(r"(com|lpt)[0-9]", stem):
            return None
    return value.lower()


def _overlap(left, right):
    return left == right or left.startswith(right + "\\") or right.startswith(left + "\\")


def _records_valid(records, identity, allowed, required):
    if type(records) is not list or len(records) > MAX_RECORDS:
        return False
    seen = set()
    for record in records:
        if type(record) is not dict or not required <= record.keys() or record.keys() - allowed:
            return False
        if not _identifier(record.get(identity)):
            return False
        key = record[identity].lower()
        if key in seen:
            return False
        seen.add(key)
    return True


def _schema_error(inventory):
    if type(inventory) is not dict or not _plain_json(inventory):
        return "invalid_inventory"
    keys = {"schema_version", "scope", "inventory_complete", "profiles", "applications", "artifacts"}
    if inventory.keys() != keys or type(inventory.get("schema_version")) is not int or inventory["schema_version"] != 1:
        return "unsupported_schema"
    if inventory["scope"] != "synthetic":
        return "live_inventory_not_supported"
    if inventory["inventory_complete"] is not True:
        return "incomplete_inventory"
    profile_keys = {"profile_id", "root"}
    app_keys = {"app_id", "product_id", "publisher", "profile_id", "install_root", "root_exclusive", "user_intent", "evidence", "display_name"}
    artifact_keys = {"artifact_id", "kind", "path", "resolved_path", "profile_id", "owner_app_ids", "sha256", "is_reparse_point", "hardlink_count", "display_name"}
    if not _records_valid(inventory["profiles"], "profile_id", profile_keys, profile_keys):
        return "invalid_or_duplicate_profiles"
    if not _records_valid(inventory["applications"], "app_id", app_keys, {"app_id", "product_id", "publisher", "profile_id", "install_root"}):
        return "invalid_or_duplicate_applications"
    for app in inventory["applications"]:
        if not _identifier(app["profile_id"]) or type(app["product_id"]) is not str or type(app["publisher"]) is not str:
            return "invalid_application_identity"
    if not _records_valid(inventory["artifacts"], "artifact_id", artifact_keys, {"artifact_id", "kind"}):
        return "invalid_or_duplicate_artifacts"
    roots = []
    for profile in inventory["profiles"]:
        root = _canonical_path(profile["root"])
        if root is None or re.fullmatch(r"[a-z]:\\users\\[^\\]+", root) is None:
            return "unsupported_profile_root"
        if root.split("\\")[-1] in ("public", "default", "default user", "all users") or root in roots:
            return "ambiguous_profile_root"
        roots.append(root)
    return None


def _root_artifact_reason(app, artifacts):
    root = _canonical_path(app["install_root"])
    expected = root + FIXTURE_EXECUTABLE
    for artifact in artifacts:
        path = _canonical_path(artifact.get("path"))
        resolved = _canonical_path(artifact.get("resolved_path"))
        owners = artifact.get("owner_app_ids")
        claims_app = type(owners) is list and app["app_id"] in owners
        overlaps_root = any(p is not None and _overlap(root, p) for p in (path, resolved))
        if artifact["kind"] in ("file", "directory") and (path is None or resolved is None):
            return "inventory_artifact_scope_ambiguity"
        if not claims_app and not overlaps_root:
            continue
        if (artifact["kind"] != "file" or path != expected or resolved != expected
                or owners != [app["app_id"]] or artifact.get("profile_id") != app["profile_id"]
                or artifact.get("sha256") != FIXTURE_HASH
                or artifact.get("is_reparse_point") is not False
                or type(artifact.get("hardlink_count")) is not int or artifact["hardlink_count"] != 1):
            return "shared_or_unknown_root_artifact"
    return None


def _application_reason(app, profiles, applications, artifacts):
    if app.get("product_id") != FIXTURE_PRODUCT or app.get("publisher") != FIXTURE_PUBLISHER:
        return "unvalidated_product_identity"
    if app.get("user_intent") != "review":
        return "user_intent_not_review"
    if app.get("root_exclusive") is not True:
        return "shared_or_unknown_root"
    profile = profiles.get(app.get("profile_id"))
    root = _canonical_path(app.get("install_root"))
    if profile is None or root is None:
        return "unknown_profile_or_root"
    if root != _canonical_path(profile["root"] + FIXTURE_ROOT_SUFFIX):
        return "unexpected_install_root"
    for other in applications:
        other_root = _canonical_path(other.get("install_root"))
        if other_root is None or other.get("profile_id") not in profiles:
            return "inventory_root_ambiguity"
        if other is not app and _overlap(root, other_root):
            return "shared_install_root"
    evidence = app.get("evidence")
    expected_keys = {"registration_product_id", "registration_source_id", "binary_product_id", "binary_source_id", "signer_sha256", "executable_sha256", "executable_path", "resolved_install_root", "root_is_reparse_point", "ancestors_unambiguous"}
    if type(evidence) is not dict or evidence.keys() != expected_keys:
        return "missing_independent_evidence"
    reg_id, bin_id = evidence["registration_source_id"], evidence["binary_source_id"]
    if not _identifier(reg_id) or not _identifier(bin_id) or reg_id.lower() == bin_id.lower():
        return "nonindependent_evidence"
    if evidence["registration_product_id"] != FIXTURE_PRODUCT or evidence["binary_product_id"] != FIXTURE_PRODUCT:
        return "identity_evidence_mismatch"
    if evidence["signer_sha256"] != FIXTURE_SIGNER or evidence["executable_sha256"] != FIXTURE_HASH:
        return "binary_evidence_mismatch"
    if _canonical_path(evidence["executable_path"]) != root + FIXTURE_EXECUTABLE:
        return "executable_evidence_mismatch"
    if evidence["root_is_reparse_point"] is not False or evidence["ancestors_unambiguous"] is not True:
        return "root_alias_uncertainty"
    if _canonical_path(evidence["resolved_install_root"]) != root:
        return "resolved_root_mismatch"
    return _root_artifact_reason(app, artifacts)


def audit(inventory):
    """Produce deterministic inert review records without modifying the input."""
    report = _report()
    error = _schema_error(inventory)
    if error:
        report["errors"].append(error)
        return report
    try:
        encoded = json.dumps(inventory, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (ValueError, OverflowError):
        report["errors"].append("invalid_inventory")
        return report
    if len(encoded) > MAX_INPUT:
        report["errors"].append("inventory_too_large")
        return report
    report["inventory_sha256"] = hashlib.sha256(encoded).hexdigest()
    profiles = {p["profile_id"]: p for p in inventory["profiles"]}
    apps = {a["app_id"]: a for a in inventory["applications"]}
    app_reasons = {key: _application_reason(app, profiles, inventory["applications"], inventory["artifacts"]) for key, app in apps.items()}
    paths = {}
    for artifact in inventory["artifacts"]:
        # Count both recorded and resolved aliases, even for unsupported kinds.
        for path in {_canonical_path(artifact.get("path")), _canonical_path(artifact.get("resolved_path"))} - {None}:
            paths.setdefault(path, set()).add(artifact["artifact_id"])
    for artifact in sorted(inventory["artifacts"], key=lambda a: a["artifact_id"]):
        reason = None
        owner_ids = artifact.get("owner_app_ids")
        app = None
        path = _canonical_path(artifact.get("path"))
        if artifact["kind"] != "file":
            reason = "unsupported_artifact_kind"
        elif type(owner_ids) is not list or len(owner_ids) != 1 or type(owner_ids[0]) is not str or owner_ids[0] not in apps:
            reason = "shared_or_unknown_owner"
        else:
            app = apps[owner_ids[0]]
            reason = app_reasons[app["app_id"]]
        if reason is None:
            expected = _canonical_path(app["install_root"] + FIXTURE_EXECUTABLE)
            if artifact.get("profile_id") != app["profile_id"]:
                reason = "profile_mismatch"
            elif path is None or path != expected:
                reason = "nonliteral_or_unowned_path"
            elif _canonical_path(artifact.get("resolved_path")) != path:
                reason = "resolved_path_mismatch"
            elif len(paths.get(path, ())) != 1:
                reason = "artifact_path_collision"
            elif artifact.get("is_reparse_point") is not False or type(artifact.get("hardlink_count")) is not int or artifact["hardlink_count"] != 1:
                reason = "artifact_alias_uncertainty"
            elif artifact.get("sha256") != FIXTURE_HASH:
                reason = "artifact_content_mismatch"
        if reason:
            report["skipped"].append({"artifact_id": artifact["artifact_id"], "status": "Skipped", "reason": reason})
        else:
            report["proposals"].append({
                "artifact_id": artifact["artifact_id"], "app_id": app["app_id"],
                "profile_id": app["profile_id"], "path": artifact["path"],
                "status": "Proposed", "action": "human_review", "reason": "exact_synthetic_ownership",
                "evidence_sources": [app["evidence"]["registration_source_id"], app["evidence"]["binary_source_id"]],
            })
    return report


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def main(argv=None, stdin=None, stdout=None):
    """JSON over explicitly selected stdin/stdout only; never opens a file."""
    args = sys.argv[1:] if argv is None else argv
    source = sys.stdin if stdin is None else stdin
    sink = sys.stdout if stdout is None else stdout
    report = _report()
    if args == []:
        report["limitations"].append("No inventory supplied; this is not a clean-host result.")
    elif args == ["--inventory-stdin"]:
        try:
            raw = source.read(MAX_INPUT + 1)
            if len(raw) > MAX_INPUT:
                raise ValueError("input too large")
            report = audit(json.loads(raw, object_pairs_hook=_unique_keys))
        except (ValueError, TypeError, RecursionError):
            report["errors"].append("invalid_json_input")
    else:
        report["errors"].append("unsupported_arguments")
    sink.write(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return 2 if report["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
