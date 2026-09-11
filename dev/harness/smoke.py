#!/usr/bin/env python3
"""Prove the isolated gnome-keyring control-socket path.

This is intentionally a narrow smoke proof, not the reusable harness lifecycle.
It never accepts or prints passwords. Run it directly:

    dev/harness/smoke.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


APPROVED_TEMP_ROOT = Path("/home/rektide/tmp-opencode")
STARTUP_TIMEOUT_SECONDS = 8.0
IO_TIMEOUT_SECONDS = 3.0
SHUTDOWN_TIMEOUT_SECONDS = 3.0
MAX_STARTUP_OUTPUT_BYTES = 64 * 1024

UNLOCK = 1
OK = 0
DENIED = 1


class SmokeFailure(RuntimeError):
    """A failed smoke-test invariant."""


class HarnessSignal(Exception):
    """A termination signal received while the harness owns a child."""

    def __init__(self, signum: int) -> None:
        super().__init__(f"received signal {signal.Signals(signum).name}")
        self.signum = signum


@dataclass(frozen=True)
class Sandbox:
    root: Path
    home: Path
    runtime: Path
    data: Path
    config: Path
    cache: Path
    state: Path
    temporary: Path
    control: Path
    session_bus: Path
    system_bus: Path
    stdout_log: Path
    stderr_log: Path
    evidence: Path
    cleanup_log: Path


@dataclass(frozen=True)
class SentinelState:
    digest: str
    mode: int
    uid: int
    gid: int
    size: int
    modified_ns: int


@dataclass(frozen=True)
class ShutdownResult:
    return_code: int
    sent_term: bool
    sent_kill: bool
    process_group_gone: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep-success",
        action="store_true",
        help="retain the scratch directory after a successful run",
    )
    parser.add_argument(
        "--self-test-failure",
        action="store_true",
        help="fail after readiness to demonstrate cleanup and retained diagnostics",
    )
    return parser.parse_args()


def create_sandbox() -> Sandbox:
    APPROVED_TEMP_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="gmell-h-", dir=APPROVED_TEMP_ROOT))
    require_mode_0700(root)
    paths = {
        name: root / name
        for name in ("home", "runtime", "data", "config", "cache", "state", "tmp", "control")
    }
    for path in paths.values():
        path.mkdir(mode=0o700)
        require_mode_0700(path)

    control_socket = paths["control"] / "control"
    if len(os.fsencode(control_socket)) >= 100:
        raise SmokeFailure(f"control socket path is too long: {control_socket}")

    return Sandbox(
        root=root,
        home=paths["home"],
        runtime=paths["runtime"],
        data=paths["data"],
        config=paths["config"],
        cache=paths["cache"],
        state=paths["state"],
        temporary=paths["tmp"],
        control=paths["control"],
        session_bus=root / "missing-session-bus",
        system_bus=root / "missing-system-bus",
        stdout_log=root / "daemon.stdout.log",
        stderr_log=root / "daemon.stderr.log",
        evidence=root / "evidence.json",
        cleanup_log=root / "cleanup.json",
    )


def require_mode_0700(path: Path) -> None:
    actual = stat.S_IMODE(path.stat().st_mode)
    if actual != 0o700:
        raise SmokeFailure(f"expected mode 0700 for {path}, got {actual:04o}")


def create_sentinel() -> tuple[Path, SentinelState]:
    descriptor, raw_path = tempfile.mkstemp(prefix="gmell-sentinel-", dir=APPROVED_TEMP_ROOT)
    path = Path(raw_path)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(b"gmellon harness isolation sentinel\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path, read_sentinel(path)


def read_sentinel(path: Path) -> SentinelState:
    contents = path.read_bytes()
    metadata = path.stat()
    return SentinelState(
        digest=hashlib.sha256(contents).hexdigest(),
        mode=stat.S_IMODE(metadata.st_mode),
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
    )


def daemon_environment(sandbox: Sandbox) -> dict[str, str]:
    # Build this map from nothing: activation and desktop-session variables are
    # absent rather than copied and selectively removed from the host session.
    return {
        "HOME": str(sandbox.home),
        "XDG_RUNTIME_DIR": str(sandbox.runtime),
        "XDG_DATA_HOME": str(sandbox.data),
        "XDG_CONFIG_HOME": str(sandbox.config),
        "XDG_CACHE_HOME": str(sandbox.cache),
        "XDG_STATE_HOME": str(sandbox.state),
        "TMPDIR": str(sandbox.temporary),
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={sandbox.session_bus}",
        "DBUS_SYSTEM_BUS_ADDRESS": f"unix:path={sandbox.system_bus}",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }


def launch_daemon(
    executable: str, sandbox: Sandbox, stderr_stream: BinaryIO
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            executable,
            "--foreground",
            "--components=secrets",
            "--control-directory",
            str(sandbox.control),
        ],
        env=daemon_environment(sandbox),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=stderr_stream,
        close_fds=True,
        start_new_session=True,
    )


def install_signal_handlers() -> dict[signal.Signals, signal.Handlers]:
    previous: dict[signal.Signals, signal.Handlers] = {}

    def interrupt(signum: int, _frame: object) -> None:
        # Ignore repeats while the first signal unwinds through owned cleanup.
        signal.signal(signum, signal.SIG_IGN)
        raise HarnessSignal(signum)

    for signum in (signal.SIGHUP, signal.SIGTERM):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, interrupt)
    return previous


def restore_signal_handlers(previous: dict[signal.Signals, signal.Handlers]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def wait_for_initialization_stdout_eof(
    process: subprocess.Popen[bytes], log: BinaryIO
) -> bytes:
    if process.stdout is None:
        raise SmokeFailure("daemon stdout was not captured")

    descriptor = process.stdout.fileno()
    output = bytearray()
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while True:
        return_code = process.poll()
        if return_code is not None:
            raise SmokeFailure(f"daemon exited during initialization with status {return_code}")

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SmokeFailure("timed out waiting for daemon initialization stdout EOF")

        readable, _, _ = select.select([descriptor], [], [], min(remaining, 0.1))
        if not readable:
            continue

        chunk = os.read(descriptor, 4096)
        if not chunk:
            break
        log.write(chunk)
        log.flush()
        output.extend(chunk)
        if len(output) > MAX_STARTUP_OUTPUT_BYTES:
            raise SmokeFailure("daemon initialization output exceeded the safety limit")

    if process.poll() is not None:
        raise SmokeFailure("daemon exited immediately after initialization stdout EOF")
    return bytes(output)


def parse_reported_environment(output: bytes) -> dict[str, str]:
    try:
        text = output.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SmokeFailure("daemon initialization output was not UTF-8") from error

    reported: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name and name.replace("_", "").isalnum():
            reported[name] = value
    return reported


def wait_for_control_socket(process: subprocess.Popen[bytes], path: Path) -> os.stat_result:
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while True:
        return_code = process.poll()
        if return_code is not None:
            raise SmokeFailure(f"daemon exited before control readiness with status {return_code}")
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if time.monotonic() >= deadline:
                raise SmokeFailure("timed out waiting for the control socket") from None
            time.sleep(0.02)
            continue

        if not stat.S_ISSOCK(metadata.st_mode):
            raise SmokeFailure(f"control path is not a socket: {path}")
        if metadata.st_uid != os.geteuid():
            raise SmokeFailure(
                f"control socket UID {metadata.st_uid} does not match effective UID {os.geteuid()}"
            )
        return metadata


def require_beneath(path: Path, root: Path) -> None:
    resolved_path = path.resolve(strict=False)
    resolved_root = root.resolve(strict=True)
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError as error:
        raise SmokeFailure(f"path escaped scratch root: {path}") from error


def validate_reported_paths(reported: dict[str, str], root: Path) -> None:
    path_names = {"GNOME_KEYRING_CONTROL", "SSH_AUTH_SOCK"}
    for name, value in reported.items():
        candidate: str | None = None
        if name in path_names:
            candidate = value
        elif name == "GPG_AGENT_INFO":
            candidate = value.split(":", 1)[0]
        elif value.startswith("unix:path="):
            candidate = value.removeprefix("unix:path=").split(",", 1)[0]
        elif value.startswith("/"):
            candidate = value

        if candidate is not None:
            if not candidate.startswith("/"):
                raise SmokeFailure(f"daemon reported a non-absolute path in {name}")
            require_beneath(Path(candidate), root)


def inspect_artifacts(root: Path) -> list[str]:
    artifacts: list[str] = []
    for path in sorted(root.rglob("*")):
        require_beneath(path, root)
        artifacts.append(str(path.relative_to(root)))
    return artifacts


def encode_unlock(password: bytes) -> bytes:
    if 0 in password:
        raise SmokeFailure("probe generated an invalid password containing NUL")
    payload_length = 4 + len(password)
    total_length = 8 + payload_length
    return struct.pack("!III", total_length, UNLOCK, len(password)) + password


def receive_exact(connection: socket.socket, length: int) -> bytes:
    received = bytearray()
    while len(received) < length:
        chunk = connection.recv(length - len(received))
        if not chunk:
            raise SmokeFailure("control socket closed before a complete response")
        received.extend(chunk)
    return bytes(received)


def unlock(control_socket: Path, daemon_pid: int, password: bytes) -> tuple[int, bytes]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(IO_TIMEOUT_SECONDS)
        connection.connect(str(control_socket))

        if hasattr(socket, "SO_PEERCRED"):
            raw_credentials = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            peer_pid, peer_uid, _ = struct.unpack("3i", raw_credentials)
            if peer_pid != daemon_pid or peer_uid != os.geteuid():
                raise SmokeFailure(
                    "connected control peer does not match the launched daemon and effective UID"
                )

        # The credential byte is a transport prelude, not part of the frame.
        connection.sendall(b"\0")
        frame = encode_unlock(password)
        connection.sendall(frame)
        response = receive_exact(connection, 8)

    total_length, result = struct.unpack("!II", response)
    if total_length != 8:
        raise SmokeFailure(f"unexpected control response length: {total_length}")
    return result, frame


def random_probe_password() -> bytes:
    # Protocol strings cannot contain NUL. Keep the probe values opaque while
    # mapping random bytes into printable ASCII without creating argv strings.
    return bytes((value % 94) + 33 for value in os.urandom(32))


def require_redacted(paths: tuple[Path, ...], sensitive_values: tuple[bytes, ...]) -> None:
    for path in paths:
        if not path.exists():
            continue
        contents = path.read_bytes()
        if any(value and value in contents for value in sensitive_values):
            raise SmokeFailure(f"sensitive probe bytes appeared in retained output: {path}")


def process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    return True


def signal_process_group(process_group: int, signum: signal.Signals) -> bool:
    try:
        os.killpg(process_group, signum)
    except ProcessLookupError:
        return False
    return True


def wait_for_process_group_exit(process_group: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while process_group_exists(process_group):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)
    return True


def terminate_process_group(process: subprocess.Popen[bytes]) -> ShutdownResult:
    process_group = process.pid
    sent_term = signal_process_group(process_group, signal.SIGTERM)
    sent_kill = False

    try:
        return_code = process.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        sent_kill = signal_process_group(process_group, signal.SIGKILL)
        return_code = process.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS)

    if not wait_for_process_group_exit(process_group, SHUTDOWN_TIMEOUT_SECONDS):
        sent_kill = signal_process_group(process_group, signal.SIGKILL) or sent_kill
        if not wait_for_process_group_exit(process_group, SHUTDOWN_TIMEOUT_SECONDS):
            raise SmokeFailure(f"owned process group {process_group} survived SIGKILL")

    if not sent_term:
        raise SmokeFailure(
            f"daemon exited before owned teardown with status {return_code}"
        )
    expected_statuses = {0, -signal.SIGTERM}
    if sent_kill:
        expected_statuses.add(-signal.SIGKILL)
    if return_code not in expected_statuses:
        raise SmokeFailure(f"daemon teardown returned abnormal status {return_code}")

    return ShutdownResult(
        return_code=return_code,
        sent_term=sent_term,
        sent_kill=sent_kill,
        process_group_gone=True,
    )


def write_evidence(
    sandbox: Sandbox,
    executable: str,
    process: subprocess.Popen[bytes],
    reported_environment: dict[str, str],
    control_metadata: os.stat_result,
    artifacts: list[str],
) -> None:
    safe_environment = daemon_environment(sandbox)
    document = {
        "daemon": {"executable": executable, "pid": process.pid},
        "isolation": {
            "kind": "configuration-and-session",
            "environment": safe_environment,
            "reported_environment": reported_environment,
        },
        "paths": {
            "scratch_root": str(sandbox.root),
            "control_directory": str(sandbox.control),
            "control_socket": str(sandbox.control / "control"),
            "login_keyring": str(sandbox.data / "keyrings" / "login.keyring"),
            "observed_artifacts": artifacts,
        },
        "checks": {
            "initialization_stdout_eof": True,
            "daemon_alive_after_initialization": True,
            "control_socket_owner_uid": control_metadata.st_uid,
            "fresh_unlock": "OK",
            "wrong_unlock": "DENIED",
            "external_sentinel_unchanged": True,
        },
    }
    sandbox.evidence.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def write_cleanup_result(
    sandbox: Sandbox, process: subprocess.Popen[bytes], result: ShutdownResult
) -> None:
    document = {
        "daemon_pid": process.pid,
        "return_code": result.return_code,
        "sent_term": result.sent_term,
        "sent_kill": result.sent_kill,
        "process_group_gone": result.process_group_gone,
    }
    sandbox.cleanup_log.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def run(keep_success: bool, self_test_failure: bool) -> None:
    old_umask = os.umask(0o077)
    previous_signal_handlers = install_signal_handlers()
    sandbox: Sandbox | None = None
    sentinel_path: Path | None = None
    sentinel_before: SentinelState | None = None
    process: subprocess.Popen[bytes] | None = None
    stdout_stream: BinaryIO | None = None
    stderr_stream: BinaryIO | None = None
    sensitive_values: tuple[bytes, ...] = ()
    success = False
    failure: BaseException | None = None
    cleanup_failure: BaseException | None = None

    try:
        executable = shutil.which("gnome-keyring-daemon", path="/usr/bin:/bin")
        if executable is None:
            raise SmokeFailure("gnome-keyring-daemon was not found in /usr/bin:/bin")

        sandbox = create_sandbox()
        sentinel_path, sentinel_before = create_sentinel()
        stdout_stream = sandbox.stdout_log.open("wb")
        stderr_stream = sandbox.stderr_log.open("wb")
        process = launch_daemon(executable, sandbox, stderr_stream)

        startup_output = wait_for_initialization_stdout_eof(process, stdout_stream)
        if process.stdout is not None:
            process.stdout.close()
        reported_environment = parse_reported_environment(startup_output)
        reported_control = reported_environment.get("GNOME_KEYRING_CONTROL")
        if reported_control != str(sandbox.control):
            raise SmokeFailure(
                "daemon did not report the explicitly selected control directory"
            )
        validate_reported_paths(reported_environment, sandbox.root)

        control_socket = sandbox.control / "control"
        control_metadata = wait_for_control_socket(process, control_socket)
        for path in (
            sandbox.home,
            sandbox.runtime,
            sandbox.data,
            sandbox.config,
            sandbox.cache,
            sandbox.state,
            sandbox.temporary,
            sandbox.control,
            control_socket,
        ):
            require_beneath(path, sandbox.root)

        if self_test_failure:
            raise SmokeFailure("injected post-readiness failure")

        password = random_probe_password()
        wrong_password = random_probe_password()
        while wrong_password == password:
            wrong_password = random_probe_password()

        first_result, first_frame = unlock(control_socket, process.pid, password)
        sensitive_values = (password, wrong_password, first_frame)
        if first_result != OK:
            raise SmokeFailure(
                f"fresh-store UNLOCK returned result {first_result}, expected OK"
            )

        login_keyring = sandbox.data / "keyrings" / "login.keyring"
        user_keystore = sandbox.data / "keyrings" / "user.keystore"
        for expected_file in (login_keyring, user_keystore):
            if not expected_file.is_file():
                raise SmokeFailure(f"fresh-store UNLOCK did not create {expected_file.name}")
            require_beneath(expected_file, sandbox.root)

        wrong_result, wrong_frame = unlock(control_socket, process.pid, wrong_password)
        sensitive_values = (*sensitive_values, wrong_frame)
        if wrong_result != DENIED:
            raise SmokeFailure(
                f"wrong-password UNLOCK returned result {wrong_result}, expected DENIED"
            )

        if process.poll() is not None:
            raise SmokeFailure("daemon exited before smoke checks completed")
        if read_sentinel(sentinel_path) != sentinel_before:
            raise SmokeFailure("external isolation sentinel changed during the smoke run")

        artifacts = inspect_artifacts(sandbox.root)
        write_evidence(
            sandbox,
            executable,
            process,
            reported_environment,
            control_metadata,
            artifacts,
        )
        success = True
    except BaseException as error:
        failure = error
    finally:
        if process is not None:
            try:
                shutdown_result = terminate_process_group(process)
                if sandbox is not None:
                    write_cleanup_result(sandbox, process, shutdown_result)
            except BaseException as error:
                cleanup_failure = error
        if stdout_stream is not None:
            stdout_stream.close()
        if stderr_stream is not None:
            stderr_stream.close()
        restore_signal_handlers(previous_signal_handlers)
        os.umask(old_umask)

        if sentinel_path is not None and sentinel_before is not None:
            try:
                if read_sentinel(sentinel_path) != sentinel_before:
                    raise SmokeFailure(
                        "external isolation sentinel changed during daemon teardown"
                    )
            except BaseException as error:
                success = False
                if failure is None:
                    failure = error
                elif cleanup_failure is None:
                    cleanup_failure = error

        if sandbox is not None and sensitive_values:
            try:
                require_redacted(
                    (
                        sandbox.stdout_log,
                        sandbox.stderr_log,
                        sandbox.evidence,
                        sandbox.cleanup_log,
                    ),
                    sensitive_values,
                )
            except BaseException as error:
                success = False
                if failure is None:
                    failure = error
                elif cleanup_failure is None:
                    cleanup_failure = error

        if success and cleanup_failure is None and sentinel_path is not None:
            sentinel_path.unlink(missing_ok=True)
        if success and cleanup_failure is None and sandbox is not None and not keep_success:
            shutil.rmtree(sandbox.root)

    if failure is not None:
        if sandbox is not None:
            print(f"  retained scratch: {sandbox.root}", file=sys.stderr)
        if sentinel_path is not None:
            print(f"  retained sentinel: {sentinel_path}", file=sys.stderr)
        if cleanup_failure is not None:
            raise SmokeFailure(
                f"{failure}; daemon cleanup also failed: {cleanup_failure}"
            ) from failure
        raise failure
    if cleanup_failure is not None:
        raise SmokeFailure(f"failed to terminate and reap the daemon: {cleanup_failure}")
    if sandbox is None:
        raise SmokeFailure("sandbox was not created")

    print("PASS: isolated control-socket smoke path")
    print("  readiness: stdout EOF + live child + owned Unix socket")
    print("  protocol: fresh UNLOCK OK; wrong UNLOCK DENIED")
    print("  isolation: configured paths under scratch; external sentinel unchanged")
    print("  lifecycle: owned process group terminated and reaped")
    if keep_success:
        print(f"  artifacts: {sandbox.root}")


def main() -> int:
    arguments = parse_args()
    try:
        run(arguments.keep_success, arguments.self_test_failure)
    except HarnessSignal as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 128 + error.signum
    except KeyboardInterrupt:
        print("FAIL: interrupted", file=sys.stderr)
        return 128 + signal.SIGINT
    except SmokeFailure as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
