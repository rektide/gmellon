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
APPROVED_TEMP_ROOT = Path("/home/rektide/tmp-opencode")
REQUIRED_TOOLS = (
    "systemd-socket-activate",
    "dbus-broker-launch",
    "gnome-keyring-daemon",
    "gdbus",
)
LAUNCHER_HOST_ENDPOINTS = (
    Path("/run/systemd/journal/socket"),
    Path("/run/dbus/system_bus_socket"),
)


def available() -> bool:
    return (
        all(shutil.which(tool, path="/usr/bin:/bin") is not None for tool in REQUIRED_TOOLS)
        and all(endpoint.is_socket() for endpoint in LAUNCHER_HOST_ENDPOINTS)
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


def wait_for_readiness(root_glob_prefix: str = "gmell-h-*") -> Path | None:
    """Block until a new harness scratch root records evidence.json."""
    roots_before = set(APPROVED_TEMP_ROOT.glob(root_glob_prefix))
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        candidates = set(APPROVED_TEMP_ROOT.glob(root_glob_prefix)) - roots_before
        ready = [c for c in candidates if (c / "evidence.json").exists()]
        if ready:
            return ready[0]
        time.sleep(0.02)
    return None


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

    def spawn_sleeping_command(
        self, seconds: str = "30"
    ) -> tuple[subprocess.Popen[str], Path]:
        """Start the harness over one long command and wait for readiness."""
        process = subprocess.Popen(
            [
                str(BROKER_PATH),
                "--",
                "/usr/bin/python3",
                "-c",
                f"import time; time.sleep({seconds})",
            ],
            cwd=REPOSITORY_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        root = wait_for_readiness()
        if root is None:
            process.kill()
            self.fail("private-broker harness did not become ready")
        return process, root

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
        self.assertEqual(
            evidence["isolation"]["no_host_service_activation_proven_by"],
            [
                "zero service directories in the private bus config",
                "ListActivatableNames returned only org.freedesktop.DBus",
            ],
        )
        # The launcher environment boundary: what reaches systemd-socket-activate
        # is not what dbus-broker-launch inherits.
        launcher_environment = evidence["isolation"]["launcher_environment"]
        self.assertIn(
            "DBUS_SESSION_BUS_ADDRESS",
            launcher_environment["passed_to_systemd_socket_activate"],
        )
        self.assertIn("whitelist", launcher_environment["reaches_dbus_broker_launch"])
        self.assertFalse(launcher_environment["dbus_system_bus_address_reaches_launcher"])
        # The harness never points the launcher composition at the real system
        # bus: any DBUS_SYSTEM_BUS_ADDRESS in the passed environment is the
        # unreachable scratch path, and systemd-socket-activate strips it
        # before dbus-broker-launch runs regardless.
        self.assertEqual(
            launcher_environment["passed_to_systemd_socket_activate"][
                "DBUS_SYSTEM_BUS_ADDRESS"
            ],
            f"unix:path={root}/missing-system-bus",
        )
        # Launcher controller contact with the host system bus is recorded as
        # an unisolated dependency, with no claim that the harness redirects it.
        controller = evidence["isolation"]["launcher_controller"]
        self.assertFalse(controller["isolated_by_harness"])
        self.assertEqual(
            controller["system_bus_socket"], "/run/dbus/system_bus_socket"
        )
        self.assertEqual(
            evidence["isolation"]["host_dependencies"][
                "launcher_controller_system_bus"
            ],
            "/run/dbus/system_bus_socket",
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
        # Lock-state non-mutation is measured, not asserted as a constant:
        # the standard Collections set and every advertised collection's
        # Locked property must be identical before and after the plain
        # OpenSession plus introspection. A fresh daemon advertises at least
        # its in-memory session collection, so the measurement is non-empty.
        self.assertEqual(probe["collections_before"], probe["collections_after"])
        self.assertEqual(probe["locked_before"], probe["locked_after"])
        self.assertTrue(probe["collections_unchanged"])
        self.assertTrue(probe["locked_state_unchanged"])
        self.assertTrue(probe["collections_before"])
        self.assertEqual(
            set(probe["locked_before"]), set(probe["collections_before"])
        )
        for path in probe["collections_before"]:
            self.assertIsInstance(probe["locked_before"][path], bool)
        # No unmeasurable behavioral claims remain in the probe record.
        self.assertNotIn("password_method_called", probe)
        self.assertNotIn("collection_lock_state_changed", probe)

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
        process, root = self.spawn_sleeping_command()
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

    def test_killed_broker_fallback_teardown_accepts_signaled_broker_launcher_exit(
        self,
    ) -> None:
        """A broker that must be KILLed must not make teardown fail.

        A job-control-stopped broker cannot act on SIGTERM within the bounded
        deadline, forcing the KILL fallback. dbus-broker-launch then reports
        its signaled child by exiting 1; teardown must accept that status so
        the fallback still reaps everything and exits on the delivered signal.
        """
        process, root = self.spawn_sleeping_command()
        evidence = json.loads((root / "evidence.json").read_text())
        broker_pid = evidence["processes"]["broker"]["pid"]
        os.kill(broker_pid, signal.SIGSTOP)
        try:
            os.kill(process.pid, signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=45)
        finally:
            # If teardown already worked this is a no-op on a dead PID.
            try:
                os.kill(broker_pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
        self.assertEqual(process.returncode, 128 + signal.SIGTERM, stdout + stderr)
        self.assertNotIn("HARNESS FAILURE", stderr)
        retained = parse_retained(stdout + stderr)
        self.retained_paths.append(retained)
        cleanup = json.loads((retained / "cleanup.json").read_text())
        children = {child["name"]: child for child in cleanup["children"]}
        self.assertEqual(
            set(children), {"command", "daemon", "broker-launcher", "broker"}
        )
        self.assertTrue(all(child["reaped"] for child in children.values()))
        self.assertTrue(all(process_absent(child["pid"]) for child in children.values()))
        broker = children["broker"]
        self.assertTrue(broker["sent_term"])
        self.assertTrue(broker["sent_kill"])
        # Upstream launcher_on_child_exit() exits 1 for a signal-killed broker.
        self.assertEqual(children["broker-launcher"]["return_code"], 1)

    def test_external_broker_death_mid_command_fails_and_reaps_everything(self) -> None:
        """A broker killed from outside must fail the run and still reap all.

        This is the deterministic bounded stand-in for broker death during a
        command: the exact broker PID from the evidence is KILLed once, only
        that process is touched, and the harness must fail loudly (no command
        completion against a dead bus) while still owning teardown.
        """
        process, root = self.spawn_sleeping_command()
        evidence = json.loads((root / "evidence.json").read_text())
        broker_pid = evidence["processes"]["broker"]["pid"]
        os.kill(broker_pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=45)
        self.assertEqual(process.returncode, 125, stdout + stderr)
        self.assertIn("HARNESS FAILURE:", stderr)
        self.assertTrue(
            any(
                phrase in stderr
                for phrase in (
                    "exited while the command was running",
                    "exited with status",
                )
            ),
            stderr,
        )
        retained = parse_retained(stdout + stderr)
        self.retained_paths.append(retained)
        cleanup = json.loads((retained / "cleanup.json").read_text())
        self.assertIsNone(cleanup["signal"])
        children = {child["name"]: child for child in cleanup["children"]}
        self.assertEqual(
            set(children), {"command", "daemon", "broker-launcher", "broker"}
        )
        self.assertTrue(all(child["reaped"] for child in children.values()))
        self.assertTrue(all(process_absent(child["pid"]) for child in children.values()))
        broker = children["broker"]
        self.assertFalse(broker["sent_term"])
        self.assertFalse(broker["sent_kill"])
        self.assertTrue(children["command"]["sent_term"])
        # The launcher observed its signal-killed broker and exited 1 itself
        # before harness teardown; teardown must adopt that status.
        self.assertEqual(children["broker-launcher"]["return_code"], 1)

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
