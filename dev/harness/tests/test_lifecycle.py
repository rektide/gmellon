#!/usr/bin/env python3
"""Focused black-box and lifecycle-race tests for the real-daemon harness."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
LIFECYCLE_PATH = REPOSITORY_ROOT / "dev" / "harness" / "lifecycle.py"


def load_lifecycle():
    specification = importlib.util.spec_from_file_location("gmell_harness_lifecycle", LIFECYCLE_PATH)
    if specification is None or specification.loader is None:
        raise RuntimeError("could not load lifecycle module")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


lifecycle = load_lifecycle()


def available() -> bool:
    return shutil.which("gnome-keyring-daemon", path="/usr/bin:/bin") is not None


def parse_retained(output: str) -> Path:
    for line in output.splitlines():
        stripped = line.strip()
        for prefix in ("artifacts: ", "retained scratch: "):
            if stripped.startswith(prefix):
                return Path(stripped.removeprefix(prefix))
    raise AssertionError(f"no retained scratch path in output:\n{output}")


def process_absent(pid: int) -> bool:
    return not Path(f"/proc/{pid}").exists()


@unittest.skipUnless(available(), "gnome-keyring-daemon is required")
class LifecycleTests(unittest.TestCase):
    retained_paths: list[Path] = []

    @classmethod
    def tearDownClass(cls) -> None:
        for path in cls.retained_paths:
            shutil.rmtree(path, ignore_errors=True)

    def run_cli(self, *arguments: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(LIFECYCLE_PATH), *arguments],
            cwd=REPOSITORY_ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def remember(self, result: subprocess.CompletedProcess[str]) -> Path:
        root = parse_retained(result.stdout + result.stderr)
        self.retained_paths.append(root)
        return root

    def test_exports_strict_isolated_environment(self) -> None:
        program = """
import json, os
from pathlib import Path
root = Path(os.environ['GMELL_HARNESS_ROOT'])
(root / 'observed-command-environment.json').write_text(json.dumps(dict(os.environ)))
"""
        result = self.run_cli("--keep-success", "--", "/usr/bin/python3", "-c", program)
        self.assertEqual(result.returncode, 0, result.stderr)
        root = self.remember(result)
        observed = json.loads((root / "observed-command-environment.json").read_text())

        self.assertEqual(observed["GMELL_HARNESS_ACTIVE"], "1")
        self.assertEqual(observed["GNOME_KEYRING_CONTROL"], str(root / "control"))
        self.assertEqual(observed["GMELL_HARNESS_CONTROL_SOCKET"], str(root / "control/control"))
        self.assertEqual(observed["HOME"], str(root / "home"))
        self.assertEqual(observed["XDG_RUNTIME_DIR"], str(root / "runtime"))
        self.assertEqual(observed["DBUS_SESSION_BUS_ADDRESS"], f"unix:path={root}/missing-session-bus")
        self.assertNotIn("SSH_AUTH_SOCK", observed)
        self.assertNotIn("NOTIFY_SOCKET", observed)
        self.assertEqual(set(observed), set(lifecycle.command_environment(
            lifecycle.Sandbox(
                root=root,
                home=root / "home",
                runtime=root / "runtime",
                data=root / "data",
                config=root / "config",
                cache=root / "cache",
                state=root / "state",
                temporary=root / "tmp",
                control=root / "control",
                session_bus=root / "missing-session-bus",
                system_bus=root / "missing-system-bus",
                stdout_log=root / "daemon.stdout.log",
                stderr_log=root / "daemon.stderr.log",
                evidence=root / "evidence.json",
                cleanup_log=root / "cleanup.json",
            ),
            int(observed["GMELL_HARNESS_DAEMON_PID"]),
            (),
        )))

        cleanup = json.loads((root / "cleanup.json").read_text())
        self.assertTrue(all(child["reaped"] for child in cleanup["children"]))
        self.assertTrue(all(process_absent(child["pid"]) for child in cleanup["children"]))

    def test_command_failure_is_propagated_and_retained(self) -> None:
        result = self.run_cli("--", "/usr/bin/python3", "-c", "raise SystemExit(42)")
        self.assertEqual(result.returncode, 42, result.stderr)
        root = self.remember(result)
        self.assertTrue((root / "daemon.stdout.log").is_file())
        self.assertTrue((root / "daemon.stderr.log").is_file())
        cleanup = json.loads((root / "cleanup.json").read_text())
        self.assertEqual(cleanup["command_return_code"], 42)
        self.assertTrue(all(child["reaped"] for child in cleanup["children"]))

    def test_nested_invocation_is_rejected_before_allocation(self) -> None:
        environment = dict(os.environ)
        environment["GMELL_HARNESS_ACTIVE"] = "1"
        result = self.run_cli("--", "/usr/bin/true", env=environment)
        self.assertEqual(result.returncode, lifecycle.HARNESS_FAILURE_EXIT)
        self.assertIn("nested lifecycle invocation is rejected", result.stderr)
        self.assertNotIn("retained scratch", result.stderr)

    def test_parallel_instances_have_disjoint_paths_and_pids(self) -> None:
        invocation = [
            str(LIFECYCLE_PATH),
            "--keep-success",
            "--",
            "/usr/bin/python3",
            "-c",
            "import time; time.sleep(0.2)",
        ]
        first = subprocess.Popen(invocation, cwd=REPOSITORY_ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        second = subprocess.Popen(invocation, cwd=REPOSITORY_ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        first_stdout, first_stderr = first.communicate(timeout=30)
        second_stdout, second_stderr = second.communicate(timeout=30)
        self.assertEqual(first.returncode, 0, first_stderr)
        self.assertEqual(second.returncode, 0, second_stderr)
        first_root = parse_retained(first_stdout + first_stderr)
        second_root = parse_retained(second_stdout + second_stderr)
        self.retained_paths.extend((first_root, second_root))
        self.assertNotEqual(first_root, second_root)
        first_evidence = json.loads((first_root / "evidence.json").read_text())
        second_evidence = json.loads((second_root / "evidence.json").read_text())
        self.assertNotEqual(first_evidence["daemon"]["pid"], second_evidence["daemon"]["pid"])
        self.assertNotEqual(
            first_evidence["paths"]["control_socket"],
            second_evidence["paths"]["control_socket"],
        )

    def test_signal_during_command_reaps_exact_children(self) -> None:
        roots_before = set(lifecycle.APPROVED_TEMP_ROOT.glob("gmell-h-*"))
        process = subprocess.Popen(
            [str(LIFECYCLE_PATH), "--", "/usr/bin/python3", "-c", "import time; time.sleep(30)"],
            cwd=REPOSITORY_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 10
        root = None
        while time.monotonic() < deadline:
            candidates = set(lifecycle.APPROVED_TEMP_ROOT.glob("gmell-h-*")) - roots_before
            ready = [candidate for candidate in candidates if (candidate / "evidence.json").exists()]
            if ready:
                root = ready[0]
                break
            time.sleep(0.02)
        self.assertIsNotNone(root, "harness did not become ready")
        os.kill(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 128 + signal.SIGTERM, stdout + stderr)
        retained = self.remember(
            subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        )
        cleanup = json.loads((retained / "cleanup.json").read_text())
        self.assertEqual(cleanup["signal"], "SIGTERM")
        self.assertTrue(all(child["reaped"] for child in cleanup["children"]))
        self.assertTrue(all(process_absent(child["pid"]) for child in cleanup["children"]))

    def test_first_signal_during_finally_is_latched_until_reap(self) -> None:
        result = lifecycle.run_command(
            ["/usr/bin/true"],
            _cleanup_started=lambda: os.kill(os.getpid(), signal.SIGTERM),
        )
        self.assertEqual(result.exit_code, 128 + signal.SIGTERM)
        self.assertTrue(result.retained)
        self.assertIsNotNone(result.scratch_root)
        root = result.scratch_root
        assert root is not None
        self.retained_paths.append(root)
        cleanup = json.loads((root / "cleanup.json").read_text())
        self.assertEqual(cleanup["signal"], "SIGTERM")
        self.assertTrue(all(child["reaped"] for child in cleanup["children"]))
        self.assertTrue(all(process_absent(child["pid"]) for child in cleanup["children"]))

    def test_term_is_followed_by_kill_only_for_a_remaining_child(self) -> None:
        roots_before = set(lifecycle.APPROVED_TEMP_ROOT.glob("gmell-h-*"))
        ignore_term = """
import signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(30)
"""
        process = subprocess.Popen(
            [str(LIFECYCLE_PATH), "--", "/usr/bin/python3", "-c", ignore_term],
            cwd=REPOSITORY_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 10
        root = None
        while time.monotonic() < deadline:
            candidates = set(lifecycle.APPROVED_TEMP_ROOT.glob("gmell-h-*")) - roots_before
            ready = [candidate for candidate in candidates if (candidate / "evidence.json").exists()]
            if ready:
                root = ready[0]
                break
            time.sleep(0.02)
        self.assertIsNotNone(root, "harness did not become ready")
        # Allow the command to install its SIGTERM disposition after launch.
        time.sleep(0.1)
        os.kill(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 128 + signal.SIGTERM, stdout + stderr)
        retained = self.remember(
            subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        )
        cleanup = json.loads((retained / "cleanup.json").read_text())
        command_cleanup = next(
            child for child in cleanup["children"] if child["name"] == "command"
        )
        daemon_cleanup = next(
            child for child in cleanup["children"] if child["name"] == "daemon"
        )
        self.assertTrue(command_cleanup["sent_term"])
        self.assertTrue(command_cleanup["sent_kill"])
        self.assertEqual(command_cleanup["return_code"], -signal.SIGKILL)
        self.assertTrue(command_cleanup["reaped"])
        self.assertFalse(daemon_cleanup["sent_kill"])
        self.assertTrue(daemon_cleanup["reaped"])

    def test_passed_environment_value_is_omitted_from_evidence(self) -> None:
        environment = dict(os.environ)
        environment["GMELL_TEST_SENSITIVE_MARKER"] = "do-not-retain-this-value"
        result = self.run_cli(
            "--pass-env",
            "GMELL_TEST_SENSITIVE_MARKER",
            "--",
            "/usr/bin/python3",
            "-c",
            "raise SystemExit(19)",
            env=environment,
        )
        self.assertEqual(result.returncode, 19, result.stderr)
        root = self.remember(result)
        retained_files = [root / "evidence.json", root / "cleanup.json", root / "daemon.stdout.log", root / "daemon.stderr.log"]
        for path in retained_files:
            self.assertNotIn(b"do-not-retain-this-value", path.read_bytes(), str(path))
        evidence = json.loads((root / "evidence.json").read_text())
        self.assertEqual(
            evidence["isolation"]["command_environment"]["GMELL_TEST_SENSITIVE_MARKER"],
            "<explicit value omitted>",
        )


if __name__ == "__main__":
    unittest.main()
