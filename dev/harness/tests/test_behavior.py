#!/usr/bin/env python3
"""Black-box acceptance test for installed-daemon behavior characterization."""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
BEHAVIOR_PATH = REPOSITORY_ROOT / "dev" / "harness" / "behavior.py"


def available() -> bool:
    return shutil.which("gnome-keyring-daemon", path="/usr/bin:/bin") is not None


@unittest.skipUnless(available(), "gnome-keyring-daemon is required")
class BehaviorTests(unittest.TestCase):
    def test_complete_matrix_is_retained_and_redacted(self) -> None:
        result = subprocess.run(
            [str(BEHAVIOR_PATH), "--keep-success"],
            cwd=REPOSITORY_ROOT,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        roots = [
            Path(line.strip().removeprefix("artifacts: "))
            for line in result.stdout.splitlines()
            if line.strip().startswith("artifacts: ")
        ]
        self.assertEqual(len(roots), 4, result.stdout)
        try:
            documents = {
                document["scenario"]: document
                for document in (
                    json.loads((root / "behavior.json").read_text(encoding="utf-8"))
                    for root in roots
                )
            }
            self.assertEqual(
                documents["core-change"]["observations"]["post_restart_b"], "OK"
            )
            self.assertEqual(
                documents["core-change"]["observations"]["post_restart_a"],
                "DENIED",
            )
            self.assertEqual(
                documents["missing-change"]["observations"][
                    "missing_change_nonempty_new"
                ],
                "OK",
            )
            self.assertEqual(
                documents["empty-unlock"]["observations"]["post_restart_empty"],
                "OK",
            )
            self.assertEqual(
                documents["transport-faults"]["observations"][
                    "supervisor_stopped_daemon"
                ],
                "NO_DAEMON",
            )
            self.assertEqual(
                documents["transport-faults"]["observations"][
                    "supervisor_sigstop_fault"
                ],
                "RESPONSE_TIMEOUT",
            )
            for root, document in zip(roots, documents.values(), strict=True):
                self.assertTrue(document["installed_context"]["daemon_version"])
                self.assertFalse(document["isolation"]["secret_service_calls"])
                self.assertTrue(document["redaction"]["artifact_scan_passed"])
                cleanup = json.loads((root / "cleanup.json").read_text(encoding="utf-8"))
                self.assertTrue(all(child["reaped"] for child in cleanup["children"]))
        finally:
            for root in roots:
                shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
