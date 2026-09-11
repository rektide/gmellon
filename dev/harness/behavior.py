#!/usr/bin/env python3
"""Characterize the installed daemon's private control-socket behavior.

Passwords are generated inside this process, never accepted through argv or
the environment, and never printed. This probe makes no Secret Service calls.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from enum import IntEnum
from pathlib import Path
from typing import BinaryIO, Callable

# lifecycle.py's Python names remain package-local implementation details. The
# sibling behavior runner reuses them so readiness, isolation, and exact-PID
# teardown have one implementation; external tools must use the executable
# interfaces documented in doc/harness/README.md.
import lifecycle


IO_TIMEOUT_SECONDS = 0.35
FAULT_TRANSITION_TIMEOUT_SECONDS = 2.0


class Operation(IntEnum):
    UNLOCK = 1
    CHANGE = 2


class DaemonResult(IntEnum):
    OK = 0
    DENIED = 1
    FAILED = 2
    NO_DAEMON = 3


class BehaviorFailure(RuntimeError):
    """An installed-daemon behavior did not match the required observation."""


class NoDaemon(BehaviorFailure):
    """The selected control socket has no listener."""


class UnresponsiveDaemon(BehaviorFailure):
    """The listener did not return a complete response before the deadline."""


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    observations: dict[str, str | int | bool]
    daemon_generations: int


@dataclass(frozen=True)
class InstalledContext:
    daemon_version: str
    daemon_testing_build: str
    platform: str
    python: str


@dataclass
class RetainedScenario:
    result: ScenarioResult
    sandbox: lifecycle.Sandbox
    sentinel_path: Path


class SensitiveValues:
    """Keep generated values available for artifact scans, then overwrite them."""

    def __init__(self) -> None:
        self.values: list[bytearray] = []

    def random_password(self) -> bytearray:
        value = bytearray((byte % 94) + 33 for byte in os.urandom(32))
        self.values.append(value)
        return value

    def distinct_password(self, *others: bytearray) -> bytearray:
        while True:
            value = self.random_password()
            if all(value != other for other in others):
                return value

    def frame(self, operation: Operation, arguments: tuple[bytearray, ...]) -> bytearray:
        payload_length = sum(4 + len(argument) for argument in arguments)
        frame = bytearray(struct.pack("!II", 8 + payload_length, operation))
        for argument in arguments:
            if 0 in argument:
                raise BehaviorFailure("generated password unexpectedly contains NUL")
            frame.extend(struct.pack("!I", len(argument)))
            frame.extend(argument)
        self.values.append(frame)
        return frame

    def scan_artifacts(self, root: Path) -> None:
        retained_files = [path for path in root.rglob("*") if path.is_file()]
        for path in retained_files:
            contents = path.read_bytes()
            for value in self.values:
                if value and bytes(value) in contents:
                    raise BehaviorFailure(
                        f"sensitive password or request frame appeared in artifact {path}"
                    )

    def clear(self) -> None:
        for value in self.values:
            value[:] = b"\0" * len(value)
        self.values.clear()


class ControlProbe:
    """Disposable one-request-per-connection control transport."""

    def __init__(
        self,
        control_socket: Path,
        daemon_pid: int,
        sensitive: SensitiveValues,
        timeout: float = IO_TIMEOUT_SECONDS,
    ) -> None:
        self.control_socket = control_socket
        self.daemon_pid = daemon_pid
        self.sensitive = sensitive
        self.timeout = timeout

    def unlock(self, password: bytearray) -> DaemonResult:
        return self.exchange(Operation.UNLOCK, (password,))

    def change(self, original: bytearray, new: bytearray) -> DaemonResult:
        return self.exchange(Operation.CHANGE, (original, new))

    def exchange(
        self, operation: Operation, arguments: tuple[bytearray, ...]
    ) -> DaemonResult:
        frame = self.sensitive.frame(operation, arguments)
        try:
            metadata = self.control_socket.lstat()
        except FileNotFoundError as error:
            raise NoDaemon("control socket is absent") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISSOCK(metadata.st_mode):
            raise BehaviorFailure("control path is not a simple Unix socket")
        if metadata.st_uid != os.geteuid():
            raise BehaviorFailure("control socket owner differs from the effective UID")

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self.timeout)
            try:
                connection.connect(str(self.control_socket))
            except (FileNotFoundError, ConnectionRefusedError) as error:
                raise NoDaemon("control socket has no listener") from error

            if not hasattr(socket, "SO_PEERCRED"):
                raise BehaviorFailure("SO_PEERCRED is required by this Linux probe")
            raw_credentials = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            peer_pid, peer_uid, _peer_gid = struct.unpack("3i", raw_credentials)
            if peer_pid != self.daemon_pid or peer_uid != os.geteuid():
                raise BehaviorFailure("connected peer is not the exact owned daemon")

            try:
                connection.sendall(b"\0")
                connection.sendall(frame)
                response = receive_exact(connection, 8)
            except TimeoutError as error:
                raise UnresponsiveDaemon("control response deadline expired") from error
            except (BrokenPipeError, ConnectionResetError) as error:
                raise BehaviorFailure("control exchange ended before a response") from error

        total_length, raw_result = struct.unpack("!II", response)
        if total_length != 8:
            raise BehaviorFailure(f"unexpected response length {total_length}")
        try:
            return DaemonResult(raw_result)
        except ValueError as error:
            raise BehaviorFailure(f"unknown daemon result {raw_result}") from error


class OwnedDaemon:
    """Behavior-owned daemon generations sharing one isolated private store."""

    def __init__(
        self,
        executable: str,
        sandbox: lifecycle.Sandbox,
        stdout_stream: BinaryIO,
        stderr_stream: BinaryIO,
        signals: lifecycle.SignalLatch,
    ) -> None:
        self.executable = executable
        self.sandbox = sandbox
        self.stdout_stream = stdout_stream
        self.stderr_stream = stderr_stream
        self.signals = signals
        self.ready: lifecycle.ReadyDaemon | None = None
        self.starting_process: subprocess.Popen[bytes] | None = None
        self.generations = 0
        self.shutdown: list[lifecycle.ChildShutdown] = []
        self.suspended = False

    @property
    def process(self):
        if self.ready is None:
            raise BehaviorFailure("no behavior-owned daemon is running")
        return self.ready.process

    def start(self) -> None:
        if self.ready is not None or self.starting_process is not None:
            raise BehaviorFailure("cannot start a second daemon generation")
        process = lifecycle.launch_daemon(
            self.executable, self.sandbox, self.stderr_stream
        )
        self.starting_process = process
        self.ready = lifecycle.prove_daemon_ready(
            process,
            self.sandbox,
            self.stdout_stream,
            self.signals,
        )
        self.starting_process = None
        self.generations += 1

    def stop(self) -> None:
        if self.ready is None:
            raise BehaviorFailure("cannot stop an absent daemon")
        if self.suspended:
            self.resume()
        process = self.ready.process
        try:
            result = lifecycle.stop_owned_daemon(process)
        finally:
            # Whether validation succeeds or fails, terminate_children either
            # reaped this exact process or raised a cleanup failure.
            if process.poll() is not None:
                self.ready = None
        self.shutdown.append(result)

    def restart(self) -> None:
        self.stop()
        self.start()

    def suspend(self) -> None:
        process = self.process
        if process.poll() is not None:
            raise BehaviorFailure("daemon exited before the owned fault transition")
        os.kill(process.pid, signal.SIGSTOP)
        self.suspended = True
        wait_for_process_state(process.pid, stopped=True)

    def resume(self) -> None:
        process = self.process
        os.kill(process.pid, signal.SIGCONT)
        wait_for_process_state(process.pid, stopped=False)
        self.suspended = False

    def probe(self, sensitive: SensitiveValues) -> ControlProbe:
        self.signals.raise_if_pending()
        process = self.process
        if process.poll() is not None:
            raise BehaviorFailure("daemon exited outside an owned transition")
        return ControlProbe(
            self.sandbox.control / "control", process.pid, sensitive
        )

    def cleanup(self) -> None:
        if self.ready is not None:
            self.stop()
        elif self.starting_process is not None:
            process = self.starting_process
            try:
                self.shutdown.append(lifecycle.stop_owned_daemon(process))
            finally:
                if process.poll() is not None:
                    self.starting_process = None


def receive_exact(connection: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise BehaviorFailure("control socket closed before a complete response")
        result.extend(chunk)
    return bytes(result)


def wait_for_process_state(pid: int, *, stopped: bool) -> None:
    deadline = time.monotonic() + FAULT_TRANSITION_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
        except FileNotFoundError as error:
            raise BehaviorFailure("owned daemon disappeared during fault transition") from error
        state_line = next(line for line in status.splitlines() if line.startswith("State:"))
        is_stopped = "T (stopped)" in state_line or "t (tracing stop)" in state_line
        if is_stopped == stopped:
            return
        time.sleep(0.01)
    expected = "stopped" if stopped else "running"
    raise BehaviorFailure(f"timed out waiting for daemon to become {expected}")


def require_result(actual: DaemonResult, expected: DaemonResult, operation: str) -> None:
    if actual != expected:
        raise BehaviorFailure(
            f"{operation} returned {actual.name}, expected {expected.name}"
        )


def require_login_files(sandbox: lifecycle.Sandbox, *, present: bool) -> None:
    paths = (
        sandbox.data / "keyrings" / "login.keyring",
        sandbox.data / "keyrings" / "user.keystore",
    )
    for path in paths:
        if path.is_file() != present:
            expectation = "exist" if present else "be absent"
            raise BehaviorFailure(f"expected {path.name} to {expectation}")
        if path.exists():
            lifecycle.require_beneath(path, sandbox.root)


def observe_core_change(
    daemon: OwnedDaemon, sandbox: lifecycle.Sandbox, sensitive: SensitiveValues
) -> dict[str, str | int | bool]:
    password_a = sensitive.random_password()
    password_b = sensitive.distinct_password(password_a)
    wrong = sensitive.distinct_password(password_a, password_b)
    empty = bytearray()

    probe = daemon.probe(sensitive)
    require_login_files(sandbox, present=False)
    require_result(probe.unlock(password_a), DaemonResult.OK, "missing-store UNLOCK")
    require_login_files(sandbox, present=True)
    require_result(probe.unlock(password_a), DaemonResult.OK, "correct UNLOCK")
    require_result(probe.unlock(wrong), DaemonResult.DENIED, "wrong UNLOCK")
    require_result(
        probe.change(password_a, empty), DaemonResult.DENIED, "CHANGE to empty password"
    )
    require_result(
        probe.unlock(password_a), DaemonResult.OK, "UNLOCK after rejected empty CHANGE"
    )
    require_result(probe.change(password_a, password_b), DaemonResult.OK, "CHANGE A-to-B")

    daemon.restart()
    probe = daemon.probe(sensitive)
    require_result(probe.unlock(password_b), DaemonResult.OK, "post-restart UNLOCK B")
    require_result(probe.unlock(password_a), DaemonResult.DENIED, "post-restart UNLOCK A")
    require_result(probe.unlock(empty), DaemonResult.DENIED, "post-restart empty UNLOCK")
    return {
        "missing_store_unlock": "OK",
        "login_files_created": True,
        "subsequent_correct_unlock": "OK",
        "wrong_unlock": "DENIED",
        "change_nonempty_to_empty": "DENIED",
        "password_unchanged_after_rejected_change": True,
        "change_a_to_b": "OK",
        "post_restart_b": "OK",
        "post_restart_a": "DENIED",
        "post_restart_empty": "DENIED",
    }


def observe_missing_change(
    daemon: OwnedDaemon, sandbox: lifecycle.Sandbox, sensitive: SensitiveValues
) -> dict[str, str | int | bool]:
    original = sensitive.random_password()
    new_password = sensitive.distinct_password(original)
    empty = bytearray()
    probe = daemon.probe(sensitive)

    require_login_files(sandbox, present=False)
    require_result(
        probe.change(original, empty),
        DaemonResult.DENIED,
        "missing-store CHANGE to empty password",
    )
    require_login_files(sandbox, present=False)
    require_result(
        probe.change(original, new_password),
        DaemonResult.OK,
        "missing-store CHANGE to nonempty password",
    )
    require_login_files(sandbox, present=True)

    daemon.restart()
    probe = daemon.probe(sensitive)
    require_result(
        probe.unlock(new_password), DaemonResult.OK, "missing-CHANGE created password"
    )
    require_result(
        probe.unlock(original), DaemonResult.DENIED, "missing-CHANGE ignored original"
    )
    return {
        "missing_change_empty_new": "DENIED",
        "empty_new_created_store": False,
        "missing_change_nonempty_new": "OK",
        "login_files_created": True,
        "post_restart_new": "OK",
        "post_restart_original": "DENIED",
    }


def observe_empty_unlock(
    daemon: OwnedDaemon, sandbox: lifecycle.Sandbox, sensitive: SensitiveValues
) -> dict[str, str | int | bool]:
    nonempty = sensitive.random_password()
    replacement = sensitive.distinct_password(nonempty)
    empty = bytearray()
    probe = daemon.probe(sensitive)

    require_login_files(sandbox, present=False)
    require_result(probe.unlock(empty), DaemonResult.OK, "missing-store empty UNLOCK")
    require_login_files(sandbox, present=True)
    daemon.restart()
    probe = daemon.probe(sensitive)
    require_result(probe.unlock(empty), DaemonResult.OK, "post-restart empty UNLOCK")
    require_result(
        probe.unlock(nonempty), DaemonResult.DENIED, "nonempty UNLOCK of empty store"
    )
    require_result(
        probe.change(empty, replacement), DaemonResult.OK, "CHANGE empty-to-nonempty"
    )
    daemon.restart()
    probe = daemon.probe(sensitive)
    require_result(
        probe.unlock(replacement), DaemonResult.OK, "post-restart replacement UNLOCK"
    )
    require_result(
        probe.unlock(empty), DaemonResult.DENIED, "post-restart former empty UNLOCK"
    )
    return {
        "missing_store_empty_unlock": "OK",
        "login_files_created": True,
        "post_restart_empty": "OK",
        "nonempty_against_empty_store": "DENIED",
        "change_empty_to_nonempty": "OK",
        "post_restart_replacement": "OK",
        "post_restart_former_empty": "DENIED",
    }


def observe_faults(
    daemon: OwnedDaemon, sandbox: lifecycle.Sandbox, sensitive: SensitiveValues
) -> dict[str, str | int | bool]:
    password = sensitive.random_password()
    require_result(
        daemon.probe(sensitive).unlock(password),
        DaemonResult.OK,
        "fault-fixture initial UNLOCK",
    )
    stopped_pid = daemon.process.pid
    daemon.stop()
    try:
        ControlProbe(
            sandbox.control / "control", stopped_pid, sensitive
        ).unlock(password)
    except NoDaemon:
        stopped_result = "NO_DAEMON"
    else:
        raise BehaviorFailure("stopped daemon unexpectedly accepted a connection")

    daemon.start()
    daemon.suspend()
    try:
        try:
            daemon.probe(sensitive).unlock(password)
        except UnresponsiveDaemon:
            unresponsive_result = "RESPONSE_TIMEOUT"
        else:
            raise BehaviorFailure("SIGSTOP-faulted daemon unexpectedly responded")
    finally:
        daemon.resume()
    require_result(
        daemon.probe(sensitive).unlock(password),
        DaemonResult.OK,
        "UNLOCK after restoring responsiveness",
    )
    return {
        "supervisor_stopped_daemon": stopped_result,
        "supervisor_sigstop_fault": unresponsive_result,
        "response_deadline_seconds": IO_TIMEOUT_SECONDS,
        "post_resume_unlock": "OK",
    }


SCENARIOS: tuple[
    tuple[
        str,
        Callable[
            [OwnedDaemon, lifecycle.Sandbox, SensitiveValues],
            dict[str, str | int | bool],
        ],
    ],
    ...,
] = (
    ("core-change", observe_core_change),
    ("missing-change", observe_missing_change),
    ("empty-unlock", observe_empty_unlock),
    ("transport-faults", observe_faults),
)


def write_scenario_evidence(
    sandbox: lifecycle.Sandbox,
    executable: str,
    context: InstalledContext,
    result: ScenarioResult,
    shutdown: list[lifecycle.ChildShutdown],
    artifact_scan_passed: bool | None,
) -> None:
    document = {
        "scenario": result.name,
        "observations": result.observations,
        "daemon": {
            "executable": executable,
            "generations": result.daemon_generations,
        },
        "installed_context": asdict(context),
        "isolation": {
            "kind": "configuration-and-session",
            "environment": lifecycle.base_environment(sandbox),
            "secret_service_calls": False,
        },
        "owned_daemon_shutdowns": [asdict(item) for item in shutdown],
        "redaction": {
            "passwords_recorded": False,
            "request_frames_recorded": False,
            "artifact_scan_passed": artifact_scan_passed,
        },
    }
    (sandbox.root / "behavior.json").write_text(
        json.dumps(document, indent=2) + "\n", encoding="utf-8"
    )


def run_scenario(
    name: str,
    observer: Callable[
        [OwnedDaemon, lifecycle.Sandbox, SensitiveValues],
        dict[str, str | int | bool],
    ],
    executable: str,
    context: InstalledContext,
    signals: lifecycle.SignalLatch,
) -> RetainedScenario:
    sandbox = lifecycle.create_sandbox()
    sentinel_path, sentinel_before = lifecycle.create_sentinel()
    stdout_stream = sandbox.stdout_log.open("wb")
    stderr_stream = sandbox.stderr_log.open("wb")
    daemon = OwnedDaemon(executable, sandbox, stdout_stream, stderr_stream, signals)
    sensitive = SensitiveValues()
    observations: dict[str, str | int | bool] | None = None
    failure: BaseException | None = None
    cleanup_failure: BaseException | None = None

    try:
        daemon.start()
        if lifecycle.read_sentinel(sentinel_path) != sentinel_before:
            raise BehaviorFailure("external sentinel changed before behavior probe")
        observations = observer(daemon, sandbox, sensitive)
        signals.raise_if_pending()
        if lifecycle.read_sentinel(sentinel_path) != sentinel_before:
            raise BehaviorFailure("external sentinel changed during behavior probe")
    except BaseException as error:
        failure = error
    finally:
        try:
            daemon.cleanup()
        except BaseException as error:
            cleanup_failure = error
        stdout_stream.close()
        stderr_stream.close()
        try:
            lifecycle.write_cleanup(sandbox, None, daemon.shutdown, signals.first)
            if observations is not None:
                result = ScenarioResult(name, observations, daemon.generations)
                write_scenario_evidence(
                    sandbox,
                    executable,
                    context,
                    result,
                    daemon.shutdown,
                    artifact_scan_passed=None,
                )
            if lifecycle.read_sentinel(sentinel_path) != sentinel_before:
                raise BehaviorFailure("external sentinel changed during owned cleanup")
            sensitive.scan_artifacts(sandbox.root)
            if observations is not None:
                write_scenario_evidence(
                    sandbox,
                    executable,
                    context,
                    result,
                    daemon.shutdown,
                    artifact_scan_passed=True,
                )
        except BaseException as error:
            if cleanup_failure is None:
                cleanup_failure = error
        finally:
            sensitive.clear()

    if cleanup_failure is not None:
        print(f"  retained scratch: {sandbox.root}", file=sys.stderr)
        print(f"  retained sentinel: {sentinel_path}", file=sys.stderr)
        raise BehaviorFailure(f"{name} cleanup or redaction failed: {cleanup_failure}")
    if failure is not None:
        print(f"  retained scratch: {sandbox.root}", file=sys.stderr)
        print(f"  retained sentinel: {sentinel_path}", file=sys.stderr)
        raise failure
    if observations is None:
        raise BehaviorFailure(f"{name} produced no observations")
    return RetainedScenario(
        ScenarioResult(name, observations, daemon.generations), sandbox, sentinel_path
    )


def run(keep_success: bool) -> list[RetainedScenario]:
    if "GMELL_HARNESS_ACTIVE" in os.environ:
        raise BehaviorFailure("behavior probe cannot run inside an active lifecycle")
    executable = shutil.which("gnome-keyring-daemon", path="/usr/bin:/bin")
    if executable is None:
        raise BehaviorFailure("gnome-keyring-daemon was not found in /usr/bin:/bin")
    context = installed_context(executable)

    old_umask = os.umask(0o077)
    signals = lifecycle.SignalLatch()
    signals.install()
    retained: list[RetainedScenario] = []
    failure: BaseException | None = None
    try:
        for name, observer in SCENARIOS:
            signals.raise_if_pending()
            retained.append(
                run_scenario(name, observer, executable, context, signals)
            )
    except BaseException as error:
        failure = error
    finally:
        signal_number = signals.first
        signals.restore()
        os.umask(old_umask)

    if failure is not None or signal_number is not None:
        for scenario in retained:
            print(f"  retained scratch: {scenario.sandbox.root}", file=sys.stderr)
            print(f"  retained sentinel: {scenario.sentinel_path}", file=sys.stderr)
        if isinstance(failure, lifecycle.SignalPending) and signal_number is not None:
            raise SystemExit(128 + signal_number)
        if failure is not None:
            raise failure
        raise SystemExit(128 + signal_number)

    for scenario in retained:
        scenario.sentinel_path.unlink(missing_ok=True)
        if not keep_success:
            shutil.rmtree(scenario.sandbox.root)
    return retained


def installed_context(executable: str) -> InstalledContext:
    version_result = subprocess.run(
        [executable, "--version"],
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        capture_output=True,
        timeout=3,
        check=False,
    )
    if version_result.returncode != 0:
        raise BehaviorFailure("gnome-keyring-daemon --version failed")
    lines = version_result.stdout.decode("utf-8").splitlines()
    if len(lines) != 2 or not lines[0].startswith("gnome-keyring-daemon: "):
        raise BehaviorFailure("gnome-keyring-daemon --version returned unexpected output")
    if not lines[1].startswith("testing: "):
        raise BehaviorFailure("gnome-keyring-daemon did not report its testing build mode")
    return InstalledContext(
        daemon_version=lines[0].removeprefix("gnome-keyring-daemon: "),
        daemon_testing_build=lines[1].removeprefix("testing: "),
        platform=platform.platform(),
        python=platform.python_version(),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep-success",
        action="store_true",
        help="retain each private scenario root after successful characterization",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        scenarios = run(arguments.keep_success)
    except BehaviorFailure as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    except lifecycle.HarnessFailure as error:
        print(f"HARNESS FAILURE: {error}", file=sys.stderr)
        return lifecycle.HARNESS_FAILURE_EXIT

    print("PASS: installed control-protocol behavior matrix")
    for scenario in scenarios:
        print(
            f"  {scenario.result.name}: observed "
            f"({scenario.result.daemon_generations} daemon generations)"
        )
        if arguments.keep_success:
            print(f"    artifacts: {scenario.sandbox.root}")
    print("  redaction: generated passwords and request frames absent from artifacts")
    print("  boundary: control socket only; no Secret Service calls")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
