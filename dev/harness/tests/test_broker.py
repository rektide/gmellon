#!/usr/bin/env python3
"""Focused black-box tests for the private dbus-broker harness mode."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
BROKER_PATH = REPOSITORY_ROOT / "dev" / "harness" / "broker.py"
PROBE_PATH = REPOSITORY_ROOT / "dev" / "harness" / "private_bus_probe.py"
REQUIRED_TOOLS = (
    "systemd-socket-activate",
    "dbus-broker-launch",
    "gnome-keyring-daemon",
    "gdbus",
)


def available() -> bool:
    return (
        all(shutil.which(tool, path="/usr/bin:/bin") is not None for tool in REQUIRED_TOOLS)
        and Path("/run/systemd/journal/socket").exists()
        and Path("/run/systemd/system").is_dir()
    )


def parse_retained(output: str) -> Path:
    for line in output.splitlines():
        stripped = line.strip()
        for prefix in ("artifacts: ", "retained scratch: "):
            if stripped.startswith(prefix):
                return Path(stripped.removeprefix(prefix))
    raise AssertionError(f"no retained scratch path in output:\n{output}")


def process_absent(pid: int) -> bool:
    return not Path(f"/proc/{pid}").exists()


@unittest.skipUnless(available(), "private dbus-broker host dependencies are required")
class BrokerTests(unittest.TestCase):
    retained_paths: list[Path] = []

    @classmethod
    def tearDownClass(cls) -> None:
        for path in cls.retained_paths:
            shutil.rmtree(path, ignore_errors=True)

    def run_cli(
        self, *arguments: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(BROKER_PATH), *arguments],
            cwd=REPOSITORY_ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=45,
            check=False,
        )

    def remember(self, result: subprocess.CompletedProcess[str]) -> Path:
        root = parse_retained(result.stdout + result.stderr)
        self.retained_paths.append(root)
        return root

    def test_exports_private_bus_and_reaps_exact_topology(self) -> None:
        program = """
import json, os
from pathlib import Path
root = Path(os.environ['GMELL_HARNESS_ROOT'])
(root / 'observed-private-environment.json').write_text(json.dumps(dict(os.environ)))
"""
        result = self.run_cli(
            "--keep-success", "--", "/usr/bin/python3", "-c", program
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        root = self.remember(result)
        observed = json.loads((root / "observed-private-environment.json").read_text())
        evidence = json.loads((root / "evidence.json").read_text())
        cleanup = json.loads((root / "cleanup.json").read_text())

        self.assertEqual(observed["GMELL_HARNESS_MODE"], "private-broker")
        self.assertEqual(observed["HOME"], str(root / "home"))
        self.assertEqual(observed["XDG_DATA_HOME"], str(root / "data"))
        self.assertEqual(observed["DBUS_SESSION_BUS_ADDRESS"], f"unix:path={root}/bus")
        self.assertEqual(
            observed["DBUS_SYSTEM_BUS_ADDRESS"], f"unix:path={root}/missing-system-bus"
        )
        self.assertNotIn("LISTEN_FDS", observed)
        self.assertNotIn("DBUS_STARTER_ADDRESS", observed)
        self.assertEqual(evidence["isolation"]["host_service_activation_directories"], [])
        self.assertEqual(
            evidence["isolation"]["activatable_names"], ["org.freedesktop.DBus"]
        )
        self.assertTrue(evidence["readiness"]["private_bus_answered"])
        self.assertEqual(
            evidence["readiness"]["name_owner_pid"],
            evidence["processes"]["daemon"]["pid"],
        )
        self.assertEqual(
            set(evidence["readiness"]["name_owners"]),
            {"org.gnome.keyring", "org.freedesktop.secrets"},
        )
        self.assertTrue(
            evidence["readiness"]["listener_fd_holders"]["broker_launcher"]
        )
        self.assertTrue(evidence["readiness"]["listener_fd_holders"]["broker"])

        names = {child["name"] for child in cleanup["children"]}
        self.assertEqual(names, {"command", "daemon", "broker-launcher", "broker"})
        self.assertTrue(all(child["reaped"] for child in cleanup["children"]))
        self.assertTrue(all(process_absent(child["pid"]) for child in cleanup["children"]))

    def test_private_session_and_interface_probe(self) -> None:
        result = self.run_cli("--keep-success", "--", str(PROBE_PATH))
        self.assertEqual(result.returncode, 0, result.stderr)
        root = self.remember(result)
        probe = json.loads((root / "private-bus-probe.json").read_text())
        self.assertTrue(probe["plain_session_opened"])
        self.assertTrue(probe["private_interface_introspectable"])
        self.assertFalse(probe["password_method_called"])
        self.assertFalse(probe["collection_lock_state_changed"])

    def test_command_failure_is_retained_redacted_and_fully_reaped(self) -> None:
        marker = "private-broker-sensitive-marker"
        environment = dict(os.environ)
        environment["GMELL_TEST_SENSITIVE_MARKER"] = marker
        result = self.run_cli(
            "--pass-env",
            "GMELL_TEST_SENSITIVE_MARKER",
            "--",
            "/usr/bin/python3",
            "-c",
            "raise SystemExit(37)",
            env=environment,
        )
        self.assertEqual(result.returncode, 37, result.stderr)
        root = self.remember(result)
        cleanup = json.loads((root / "cleanup.json").read_text())
        self.assertEqual(cleanup["command_return_code"], 37)
        self.assertTrue(all(child["reaped"] for child in cleanup["children"]))
        self.assertTrue(all(process_absent(child["pid"]) for child in cleanup["children"]))
        for path in root.rglob("*"):
            if path.is_file():
                self.assertNotIn(marker.encode(), path.read_bytes(), str(path))

    def test_signal_during_command_reaps_broker_daemon_and_command(self) -> None:
        roots_before = set(Path("/home/rektide/tmp-opencode").glob("gmell-h-*"))
        process = subprocess.Popen(
            [
                str(BROKER_PATH),
                "--",
                "/usr/bin/python3",
                "-c",
                "import time; time.sleep(30)",
            ],
            cwd=REPOSITORY_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 15
        root = None
        while time.monotonic() < deadline:
            candidates = (
                set(Path("/home/rektide/tmp-opencode").glob("gmell-h-*"))
                - roots_before
            )
            ready = [candidate for candidate in candidates if (candidate / "evidence.json").exists()]
            if ready:
                root = ready[0]
                break
            time.sleep(0.02)
        self.assertIsNotNone(root, "private-broker harness did not become ready")
        os.kill(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=30)
        self.assertEqual(process.returncode, 128 + signal.SIGTERM, stdout + stderr)
        retained = parse_retained(stdout + stderr)
        self.retained_paths.append(retained)
        cleanup = json.loads((retained / "cleanup.json").read_text())
        self.assertEqual(cleanup["signal"], "SIGTERM")
        self.assertEqual(
            {child["name"] for child in cleanup["children"]},
            {"command", "daemon", "broker-launcher", "broker"},
        )
        self.assertTrue(all(child["reaped"] for child in cleanup["children"]))
        self.assertTrue(all(process_absent(child["pid"]) for child in cleanup["children"]))

    def test_parallel_instances_use_disjoint_buses_and_processes(self) -> None:
        invocation = [
            str(BROKER_PATH),
            "--keep-success",
            "--",
            "/usr/bin/python3",
            "-c",
            "import time; time.sleep(0.2)",
        ]
        first = subprocess.Popen(
            invocation,
            cwd=REPOSITORY_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        second = subprocess.Popen(
            invocation,
            cwd=REPOSITORY_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        first_stdout, first_stderr = first.communicate(timeout=45)
        second_stdout, second_stderr = second.communicate(timeout=45)
        self.assertEqual(first.returncode, 0, first_stderr)
        self.assertEqual(second.returncode, 0, second_stderr)
        first_root = parse_retained(first_stdout + first_stderr)
        second_root = parse_retained(second_stdout + second_stderr)
        self.retained_paths.extend((first_root, second_root))
        first_evidence = json.loads((first_root / "evidence.json").read_text())
        second_evidence = json.loads((second_root / "evidence.json").read_text())
        self.assertNotEqual(first_root, second_root)
        self.assertNotEqual(
            first_evidence["paths"]["bus_socket"],
            second_evidence["paths"]["bus_socket"],
        )
        for process_name in ("broker_launcher", "broker", "daemon"):
            self.assertNotEqual(
                first_evidence["processes"][process_name]["pid"],
                second_evidence["processes"][process_name]["pid"],
            )


if __name__ == "__main__":
    unittest.main()
