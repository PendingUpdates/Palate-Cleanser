"""Independent contract tests. All Windows artifacts are inert Python strings.

No legacy script, platform collector, live registry, or Windows host is used.
"""

import ast
import copy
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import unittest
from contextlib import ExitStack
from unittest.mock import patch
import urllib.request

SOURCE_PATH = Path(__file__).resolve().parents[1] / "audit_candidate.py"


def blocked_platform():
    """Trap direct I/O, process execution and mutators during planner calls."""
    stack = ExitStack()
    names = [
        "builtins.open", "io.open", "os.open", "os.system", "os.popen",
        "os.unlink", "os.remove", "os.rmdir", "os.mkdir", "os.makedirs",
        "os.rename", "os.replace", "os.chmod", "os.chown", "os.listdir",
        "os.scandir", "os.stat", "os.lstat", "os.readlink", "os.symlink",
        "os.link", "subprocess.run", "subprocess.Popen", "subprocess.call",
        "subprocess.check_call", "subprocess.check_output", "socket.socket",
        "socket.create_connection", "urllib.request.urlopen", "shutil.rmtree",
        "shutil.move", "shutil.copy", "shutil.copy2", "shutil.copytree",
        "pathlib.Path.open", "pathlib.Path.read_text", "pathlib.Path.read_bytes",
        "pathlib.Path.write_text", "pathlib.Path.write_bytes", "pathlib.Path.mkdir",
        "pathlib.Path.unlink", "pathlib.Path.rename", "pathlib.Path.replace",
        "pathlib.Path.rmdir", "pathlib.Path.glob", "pathlib.Path.rglob",
        "pathlib.Path.resolve", "pathlib.Path.stat", "pathlib.Path.exists",
    ]
    for name in names:
        stack.enter_context(patch(name, side_effect=AssertionError("Forbidden platform access: " + name)))
    return stack


def fixture(profile_id="alice", profile_root=r"C:\Users\Alice", app_id="app-a", artifact_id="file-a"):
    root = profile_root + r"\AppData\Local\AuditFixtureBrowser"
    exe = root + r"\fixture-browser.exe"
    product = "org.example.audit-fixture-browser"
    return {
        "schema_version": 1,
        "scope": "synthetic",
        "inventory_complete": True,
        "profiles": [{"profile_id": profile_id, "root": profile_root}],
        "applications": [{
            "app_id": app_id,
            "product_id": product,
            "publisher": "Example Synthetic Publisher",
            "profile_id": profile_id,
            "install_root": root,
            "root_exclusive": True,
            "user_intent": "review",
            "evidence": {
                "registration_product_id": product,
                "registration_source_id": "reg-" + app_id,
                "binary_product_id": product,
                "binary_source_id": "bin-" + app_id,
                "signer_sha256": "a" * 64,
                "executable_sha256": "b" * 64,
                "executable_path": exe,
                "resolved_install_root": root,
                "root_is_reparse_point": False,
                "ancestors_unambiguous": True,
            },
        }],
        "artifacts": [{
            "artifact_id": artifact_id,
            "kind": "file",
            "path": exe,
            "resolved_path": exe,
            "profile_id": profile_id,
            "owner_app_ids": [app_id],
            "sha256": "b" * 64,
            "is_reparse_point": False,
            "hardlink_count": 1,
        }],
    }


class AuditSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE_PATH.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source, str(SOURCE_PATH))
        # The pure planner must not load a platform adapter even at import time.
        allowed = {"argparse", "collections", "copy", "dataclasses", "hashlib", "json", "re", "sys", "typing", "__future__"}
        for node in ast.walk(cls.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] not in allowed:
                        raise AssertionError("Unexpected candidate import: " + alias.name)
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[0] not in allowed:
                    raise AssertionError("Unexpected candidate import: " + str(node.module))
        cls.namespace = {"__name__": "audit_candidate_under_test", "__file__": str(SOURCE_PATH)}
        with blocked_platform():
            exec(compile(cls.tree, str(SOURCE_PATH), "exec"), cls.namespace)
        cls.audit = staticmethod(cls.namespace["audit"])
        cls.main = staticmethod(cls.namespace["main"])

    def run_audit(self, inventory):
        before = copy.deepcopy(inventory)
        with blocked_platform():
            result = self.audit(inventory)
        self.assertEqual(inventory, before, "Planner mutated supplied inventory")
        self.assertEqual(result["mode"], "Audit")
        self.assertEqual(result["display_name"], "Palate Cleanser")
        self.assertEqual(result["evidence_scope"], "supplied_synthetic_inventory")
        self.assertEqual(result["changes"], [])
        self.assertEqual(result["schema_version"], 1)
        for proposal in result["proposals"]:
            self.assertEqual(proposal["status"], "Proposed")
            self.assertEqual(proposal["action"], "human_review")
            self.assertFalse(any(callable(value) for value in proposal.values()))
        for skipped in result["skipped"]:
            self.assertTrue(skipped["reason"])
        return result

    def assert_skipped(self, inventory):
        report = self.run_audit(inventory)
        self.assertEqual(report["proposals"], [])
        self.assertTrue(report["skipped"] or report["errors"])
        return report

    def test_correlated_exact_fixture_proposes_review_only(self):
        report = self.run_audit(fixture())
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["skipped"], [])
        self.assertEqual(len(report["proposals"]), 1)
        proposal = report["proposals"][0]
        self.assertEqual(proposal["artifact_id"], "file-a")
        self.assertEqual(proposal["app_id"], "app-a")
        self.assertEqual(proposal["profile_id"], "alice")
        self.assertEqual(proposal["reason"], "exact_synthetic_ownership")

    def test_repeat_audit_is_deterministic_and_nonmutating(self):
        inventory = fixture()
        original = json.dumps(inventory, sort_keys=True)
        first = self.run_audit(inventory)
        second = self.run_audit(inventory)
        self.assertEqual(first, second)
        self.assertEqual(json.dumps(inventory, sort_keys=True), original)
        first["proposals"][0]["path"] = "edited report"
        self.assertEqual(json.dumps(inventory, sort_keys=True), original)
        self.assertNotEqual(self.run_audit(inventory), first)

    def test_missing_corrobation_never_proposes(self):
        keys = list(fixture()["applications"][0]["evidence"])
        for key in keys:
            with self.subTest(key=key):
                data = fixture()
                del data["applications"][0]["evidence"][key]
                self.assert_skipped(data)

    def test_publisher_identity_and_hashes_each_required(self):
        edits = [
            ("publisher", "Example Synthetic Publisher subsidiary"),
            ("product_id", "other.product.same.publisher"),
            ("root_exclusive", False), ("user_intent", "keep"),
            ("user_intent", "unknown"), ("profile_id", "bob"),
        ]
        for key, value in edits:
            with self.subTest(key=key, value=value):
                data = fixture()
                data["applications"][0][key] = value
                self.assert_skipped(data)
        evidence_edits = [
            ("registration_product_id", "other.product"),
            ("binary_product_id", "other.product"),
            ("signer_sha256", "c" * 64),
            ("executable_sha256", "c" * 64),
            ("binary_source_id", "reg-app-a"),
            ("registration_source_id", ""),
            ("root_is_reparse_point", True),
            ("ancestors_unambiguous", False),
            ("resolved_install_root", r"C:\Users\Alice\AppData\Local\Other"),
        ]
        for key, value in evidence_edits:
            with self.subTest(evidence_key=key):
                data = fixture()
                data["applications"][0]["evidence"][key] = value
                self.assert_skipped(data)

    def test_all_real_product_lookalikes_are_unknown(self):
        # Real display strings here are harmless corpus labels, not real software.
        corpus = [
            ("Shift", "Shift Technologies, Inc.", r"Shift\chromium\shift.exe"),
            ("Pulse Browser", "pulse-browser contributors", r"Programs\PulseBrowser\pulsebrowser.exe"),
            ("Pulse Secure", "Ivanti", r"Pulse Secure\PulseSecureService.exe"),
            ("Pulseway", "MMSOFT Design", r"Pulseway\PCMonitorSrv.exe"),
            ("Microsoft.ACE.OLEDB.16.0", "Microsoft", r"OFFICE16\ACEOLEDB.DLL"),
            ("AceReader Pro", "StepWare", r"AceReader Pro\ace.exe"),
            ("Acer Care Center", "Acer", r"Acer\AcerCCTMon.exe"),
            ("SIMATIC WinCC WebNavigator", "Siemens", r"Siemens\WebNavigator\WinCCViewerRT.exe"),
            ("Waves MaxxAudio", "Waves", r"Waves\WavesSvc64.exe"),
            ("Wavebox", "Wavebox", r"Wavebox\wavebox.exe"),
            ("BlazeRush", "Targem Games", r"BlazeRush\BlazeRush.exe"),
            ("Redshift", "Maxon", r"Redshift\redshift.exe"),
            ("OpenShift", "Red Hat", r"OpenShift\openshift.exe"),
            ("PulseAudio", "PulseAudio", r"PulseAudio\pulseaudio.exe"),
            ("Wave Browser", "Wavesor Software", r"WaveBrowser\wavebrowser.exe"),
            ("Ace AI Browser", "Unknown", r"Ace\Ace\Application\ace.exe"),
        ]
        for name, publisher, suffix in corpus:
            with self.subTest(name=name):
                data = fixture()
                app = data["applications"][0]
                app["product_id"] = name
                app["publisher"] = publisher
                app["evidence"]["registration_product_id"] = name
                app["evidence"]["binary_product_id"] = name
                artifact = data["artifacts"][0]
                artifact["path"] = artifact["resolved_path"] = "C:\\Users\\Alice\\AppData\\Local\\" + suffix
                self.assert_skipped(data)

    def test_shared_publishers_and_install_roots_are_skipped(self):
        original = fixture()
        root = original["applications"][0]["install_root"]
        for other_root in [root, root.lower(), root + r"\OtherProduct", r"C:\Users\Alice\AppData\Local"]:
            with self.subTest(other_root=other_root):
                data = fixture()
                data["applications"].append({
                    "app_id": "other-app", "product_id": "unknown.product",
                    "publisher": "Example Synthetic Publisher", "profile_id": "alice",
                    "install_root": other_root,
                })
                self.assert_skipped(data)

    def test_unknown_or_multiple_owners_are_skipped(self):
        for owners in [[], ["unknown"], ["app-a", "unknown"], ["app-a", "app-a"]]:
            with self.subTest(owners=owners):
                data = fixture()
                data["artifacts"][0]["owner_app_ids"] = owners
                self.assert_skipped(data)

    def test_unreviewed_kinds_never_propose(self):
        for kind in ["directory", "process", "service", "registry", "registry_value", "scheduled_task", "uninstaller", "shortcut", "browser_setting", "startup", "device", "appx", "unknown"]:
            with self.subTest(kind=kind):
                data = fixture()
                data["artifacts"][0]["kind"] = kind
                self.assert_skipped(data)

    def test_file_ownership_links_and_hash_required(self):
        for key in ["resolved_path", "profile_id", "owner_app_ids", "sha256", "is_reparse_point", "hardlink_count"]:
            with self.subTest(missing=key):
                data = fixture()
                del data["artifacts"][0][key]
                self.assert_skipped(data)
        edits = [("sha256", "c" * 64), ("profile_id", "bob"), ("is_reparse_point", True), ("hardlink_count", 2), ("hardlink_count", 0), ("resolved_path", r"C:\Users\Bob\other.exe")]
        for key, value in edits:
            with self.subTest(key=key, value=value):
                data = fixture()
                data["artifacts"][0][key] = value
                self.assert_skipped(data)

    def test_path_aliases_and_ambiguous_paths_are_skipped(self):
        valid = fixture()["artifacts"][0]["path"]
        aliases = [
            r"..\fixture-browser.exe", r"C:fixture-browser.exe",
            r"\\host\share\fixture-browser.exe", r"\\?\C:\Users\Alice\fixture-browser.exe",
            r"\\.\C:\Users\Alice\fixture-browser.exe", valid + ":alternate",
            valid.replace("AuditFixtureBrowser", "AuditFixtureBrowser."),
            valid.replace("AuditFixtureBrowser", "AuditFixtureBrowser "),
            valid.replace("AuditFixtureBrowser", "AUDITF~1"),
            valid.replace("AuditFixtureBrowser", "Other\\..\\AuditFixtureBrowser"),
            valid.replace("AuditFixtureBrowser", "Audit*Browser"),
            valid.replace("AuditFixtureBrowser", "Audit?Browser"),
            valid.replace("Alice", "%USERNAME%"),
            valid.replace("\\", "/"), valid + " ", valid + ".", valid + "\x00",
        ]
        for alias in aliases:
            with self.subTest(alias=repr(alias)):
                data = fixture()
                data["artifacts"][0]["path"] = alias
                data["artifacts"][0]["resolved_path"] = alias
                self.assert_skipped(data)

    def test_unproven_sibling_contradicts_exclusive_root(self):
        data = fixture()
        sibling = copy.deepcopy(data["artifacts"][0])
        sibling["artifact_id"] = "user-notes"
        sibling["path"] = sibling["resolved_path"] = data["applications"][0]["install_root"] + r"\user-notes.txt"
        data["artifacts"].append(sibling)
        report = self.run_audit(data)
        self.assertEqual(report["proposals"], [])
        self.assertEqual({s["artifact_id"] for s in report["skipped"]}, {"file-a", "user-notes"})

    def test_proven_disjoint_unrelated_file_does_not_contaminate_fixture(self):
        data = fixture()
        unrelated = copy.deepcopy(data["artifacts"][0])
        unrelated["artifact_id"] = "unrelated-notes"
        unrelated["path"] = unrelated["resolved_path"] = r"C:\Users\Alice\Documents\project-notes.txt"
        unrelated["owner_app_ids"] = []
        unrelated["sha256"] = "c" * 64
        data["artifacts"].append(unrelated)
        report = self.run_audit(data)
        self.assertEqual([p["artifact_id"] for p in report["proposals"]], ["file-a"])
        self.assertEqual([s["artifact_id"] for s in report["skipped"]], ["unrelated-notes"])

    def test_duplicate_ids_and_case_aliased_paths_fail_closed(self):
        for collection in ["profiles", "applications", "artifacts"]:
            with self.subTest(collection=collection):
                data = fixture()
                data[collection].append(copy.deepcopy(data[collection][0]))
                report = self.assert_skipped(data)
                self.assertTrue(report["errors"])
        data = fixture()
        other = copy.deepcopy(data["artifacts"][0])
        other["artifact_id"] = "alias-file"
        other["path"] = other["resolved_path"] = other["path"].upper()
        data["artifacts"].append(other)
        self.assert_skipped(data)

    def test_multiple_profiles_remain_separate(self):
        data = fixture()
        bob = fixture("bob", r"C:\Users\Bob", "app-b", "file-b")
        for collection in ["profiles", "applications", "artifacts"]:
            data[collection].extend(bob[collection])
        report = self.run_audit(data)
        self.assertEqual({(p["profile_id"], p["app_id"], p["artifact_id"]) for p in report["proposals"]}, {("alice", "app-a", "file-a"), ("bob", "app-b", "file-b")})
        data["artifacts"][1]["owner_app_ids"] = ["app-a"]
        report = self.run_audit(data)
        # Bob's path claiming Alice's app contradicts ownership for both
        # implicated apps; neither root is sufficiently corroborated now.
        self.assertEqual(report["proposals"], [])
        self.assertEqual({s["artifact_id"] for s in report["skipped"]}, {"file-a", "file-b"})

    def test_invalid_top_level_inventory_fails_closed(self):
        for value in [None, [], "inventory", 1, True, {}, {"schema_version": 2}]:
            with self.subTest(value=value):
                result = self.run_audit(value)
                self.assertEqual(result["proposals"], [])
                self.assertTrue(result["errors"])
        for key, value in [("schema_version", True), ("scope", "live"), ("inventory_complete", False), ("inventory_complete", "true"), ("applications", None), ("artifacts", {}), ("profiles", "alice")]:
            with self.subTest(key=key, value=value):
                data = fixture()
                data[key] = value
                result = self.run_audit(data)
                self.assertEqual(result["proposals"], [])
                self.assertTrue(result["errors"])

    def test_cli_default_only_reports_empty_audit(self):
        output = io.StringIO()
        with blocked_platform():
            result = self.main([], stdin=io.StringIO(""), stdout=output)
        self.assertIn(result, (None, 0))
        report = json.loads(output.getvalue())
        self.assertEqual(report["mode"], "Audit")
        self.assertEqual(report["changes"], [])
        self.assertEqual(report["proposals"], [])

    def test_cli_only_accepts_supplied_stdin_inventory(self):
        output = io.StringIO()
        with blocked_platform():
            result = self.main(["--inventory-stdin"], stdin=io.StringIO(json.dumps(fixture())), stdout=output)
        self.assertIn(result, (None, 0))
        report = json.loads(output.getvalue())
        self.assertEqual(len(report["proposals"]), 1)
        self.assertEqual(report["changes"], [])

    def test_cli_malformed_json_and_unknown_modes_are_rejected(self):
        output = io.StringIO()
        with blocked_platform():
            result = self.main(["--inventory-stdin"], stdin=io.StringIO('{"broken":'), stdout=output)
        report = json.loads(output.getvalue())
        self.assertTrue(report["errors"])
        self.assertEqual(report["proposals"], [])
        for args in [["--apply"], ["--remove"], ["--inventory", "C:\\Windows"], ["--mode", "Remove"]]:
            with self.subTest(args=args):
                output = io.StringIO()
                with blocked_platform(), patch("sys.stderr", new=io.StringIO()):
                    try:
                        result = self.main(args, stdin=io.StringIO(""), stdout=output)
                    except SystemExit as exc:
                        result = exc.code
                self.assertNotIn(result, (None, 0))

    def test_source_has_no_external_dispatch_or_mutator_interface(self):
        forbidden = {"eval", "exec", "compile", "__import__", "getattr", "setattr", "open", "input", "breakpoint"}
        function_names = set()
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_names.add(node.name)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, forbidden)
        self.assertFalse(function_names.intersection({"apply", "remove", "uninstall", "execute", "collect", "scan"}))


if __name__ == "__main__":
    unittest.main()
