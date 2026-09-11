#!/usr/bin/env python3
"""Run one command with a fresh, isolated gnome-keyring-daemon.

The daemon and command receive environments assembled from an empty mapping.
Use ``--pass-env NAME`` for the small number of caller variables a test needs.
Run directly for the complete command-line contract::

    dev/harness/lifecycle.py -- command arg ...
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Sequence


APPROVED_TEMP_ROOT = Path("/home/rektide/tmp-opencode")
STARTUP_TIMEOUT_SECONDS = 8.0
SHUTDOWN_TIMEOUT_SECONDS = 3.0
MAX_STARTUP_OUTPUT_BYTES = 64 * 1024
HARNESS_FAILURE_EXIT = 125
HANDLED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)

PROTECTED_ENVIRONMENT = {
    "DBUS_SESSION_BUS_ADDRESS",
    "DBUS_SYSTEM_BUS_ADDRESS",
    "DESKTOP_AUTOSTART_ID",
    "DESKTOP_STARTUP_ID",
    "GNOME_KEYRING_CONTROL",
    "GNOME_KEYRING_PID",
    "GPG_AGENT_INFO",
    "HOME",
    "LANG",
    "LC_ALL",
    "NOTIFY_SOCKET",
    "PATH",
    "SSH_AUTH_SOCK",
    "TMPDIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_ID",
    "XDG_STATE_HOME",
}
PROTECTED_PREFIXES = ("DBUS_STARTER_", "GMELL_HARNESS_", "LISTEN_")


class HarnessFailure(RuntimeError):
    """A lifecycle or isolation invariant failed."""


class SignalPending(HarnessFailure):
    """Internal control flow indicating that teardown should start."""


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
class ChildShutdown:
    name: str
    pid: int
    return_code: int
    sent_term: bool
    sent_kill: bool
    reaped: bool


@dataclass(frozen=True)
class SentinelState:
    digest: str
    mode: int
    uid: int
    gid: int
    size: int
    modified_ns: int


@dataclass(frozen=True)
class RunResult:
    exit_code: int
    scratch_root: Path | None
    retained: bool


class SignalLatch:
    """Record the first handled signal without throwing from a handler.

    Raising from a Python signal handler can interrupt any instruction,
    including a child ``wait()`` in ``finally``. This latch stays installed
    until all owned children have been reaped. Polling points notice it during
    ordinary work; signals arriving during teardown are merely recorded.
    """

    def __init__(self) -> None:
        self.first: int | None = None
        self.previous: dict[signal.Signals, signal.Handlers] = {}

    def install(self) -> None:
        def latch(signum: int, _frame: object) -> None:
            if self.first is None:
                self.first = signum

        for signum in HANDLED_SIGNALS:
            self.previous[signum] = signal.getsignal(signum)
            signal.signal(signum, latch)

    def restore(self) -> None:
        for signum, handler in self.previous.items():
            signal.signal(signum, handler)

    def raise_if_pending(self) -> None:
        if self.first is not None:
            raise SignalPending(
                f"received {signal.Signals(self.first).name}; beginning owned teardown"
            )


def require_mode_0700(path: Path) -> None:
    actual = stat.S_IMODE(path.stat().st_mode)
    if actual != 0o700:
        raise HarnessFailure(f"expected mode 0700 for {path}, got {actual:04o}")


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
        raise HarnessFailure(f"control socket path is too long: {control_socket}")

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


def base_environment(sandbox: Sandbox) -> dict[str, str]:
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


def command_environment(
    sandbox: Sandbox,
    daemon_pid: int,
    pass_environment: Sequence[str],
) -> dict[str, str]:
    environment = base_environment(sandbox)
    environment.update(
        {
            "GNOME_KEYRING_CONTROL": str(sandbox.control),
            "GMELL_HARNESS_ACTIVE": "1",
            "GMELL_HARNESS_ROOT": str(sandbox.root),
            "GMELL_HARNESS_CONTROL_DIR": str(sandbox.control),
            "GMELL_HARNESS_CONTROL_SOCKET": str(sandbox.control / "control"),
            "GMELL_HARNESS_DAEMON_PID": str(daemon_pid),
            "GMELL_HARNESS_DAEMON_STDOUT": str(sandbox.stdout_log),
            "GMELL_HARNESS_DAEMON_STDERR": str(sandbox.stderr_log),
            "GMELL_HARNESS_EVIDENCE": str(sandbox.evidence),
            "GMELL_HARNESS_CLEANUP": str(sandbox.cleanup_log),
        }
    )

    for name in pass_environment:
        if not name or not name.replace("_", "a").isalnum() or name[0].isdigit():
            raise HarnessFailure(f"invalid environment variable name for --pass-env: {name!r}")
        if name in PROTECTED_ENVIRONMENT or name.startswith(PROTECTED_PREFIXES):
            raise HarnessFailure(f"--pass-env cannot override protected variable {name}")
        if name not in os.environ:
            raise HarnessFailure(f"--pass-env requested unset variable {name}")
        environment[name] = os.environ[name]
    return environment


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
        env=base_environment(sandbox),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=stderr_stream,
        close_fds=True,
        start_new_session=True,
    )


def wait_for_initialization_stdout_eof(
    process: subprocess.Popen[bytes],
    log: BinaryIO,
    signals: SignalLatch,
    deadline: float,
) -> bytes:
    if process.stdout is None:
        raise HarnessFailure("daemon stdout was not captured")
    descriptor = process.stdout.fileno()
    output = bytearray()
    while True:
        signals.raise_if_pending()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return_code = process.poll()
            if return_code is not None:
                raise HarnessFailure(
                    "timed out draining initialization stdout after daemon exited "
                    f"with status {return_code}"
                )
            raise HarnessFailure("timed out waiting for daemon initialization stdout EOF")
        readable, _, _ = select.select([descriptor], [], [], min(remaining, 0.05))
        if not readable:
            continue
        chunk = os.read(descriptor, 4096)
        if not chunk:
            break
        log.write(chunk)
        log.flush()
        output.extend(chunk)
        if len(output) > MAX_STARTUP_OUTPUT_BYTES:
            raise HarnessFailure("daemon initialization output exceeded the safety limit")
    if process.poll() is not None:
        raise HarnessFailure(
            f"daemon exited during initialization with status {process.returncode}"
        )
    return bytes(output)


def parse_reported_environment(output: bytes) -> dict[str, str]:
    try:
        text = output.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HarnessFailure("daemon initialization output was not UTF-8") from error
    reported: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name and name.replace("_", "").isalnum():
            reported[name] = value
    return reported


def require_beneath(path: Path, root: Path) -> None:
    resolved_path = path.resolve(strict=False)
    resolved_root = root.resolve(strict=True)
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError as error:
        raise HarnessFailure(f"path escaped scratch root: {path}") from error


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
                raise HarnessFailure(f"daemon reported a non-absolute path in {name}")
            require_beneath(Path(candidate), root)


def wait_for_control_socket(
    process: subprocess.Popen[bytes], path: Path, signals: SignalLatch, deadline: float
) -> os.stat_result:
    while True:
        signals.raise_if_pending()
        return_code = process.poll()
        if return_code is not None:
            raise HarnessFailure(
                f"daemon exited before control readiness with status {return_code}"
            )
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if time.monotonic() >= deadline:
                raise HarnessFailure("timed out waiting for the control socket") from None
            time.sleep(0.02)
            continue
        if not stat.S_ISSOCK(metadata.st_mode):
            raise HarnessFailure(f"control path is not a socket: {path}")
        if metadata.st_uid != os.geteuid():
            raise HarnessFailure(
                f"control socket UID {metadata.st_uid} does not match effective UID {os.geteuid()}"
            )
        return metadata


def wait_for_command(
    command: subprocess.Popen[bytes], daemon: subprocess.Popen[bytes], signals: SignalLatch
) -> int:
    while True:
        signals.raise_if_pending()
        return_code = command.poll()
        if return_code is not None:
            return return_code
        daemon_code = daemon.poll()
        if daemon_code is not None:
            raise HarnessFailure(
                f"daemon exited with status {daemon_code} while the command was running"
            )
        time.sleep(0.05)


def terminate_children(
    children: Sequence[tuple[subprocess.Popen[bytes], str]],
) -> list[ChildShutdown]:
    """TERM all live exact PIDs, then KILL only survivors, and reap each."""

    return_codes: dict[int, int] = {}
    sent_term: set[int] = set()
    sent_kill: set[int] = set()

    for process, _name in children:
        return_code = process.poll()
        if return_code is None:
            process.terminate()
            sent_term.add(process.pid)
        else:
            return_codes[process.pid] = return_code

    term_deadline = time.monotonic() + SHUTDOWN_TIMEOUT_SECONDS
    while len(return_codes) < len(children) and time.monotonic() < term_deadline:
        for process, _name in children:
            if process.pid in return_codes:
                continue
            return_code = process.poll()
            if return_code is not None:
                return_codes[process.pid] = return_code
        if len(return_codes) < len(children):
            time.sleep(0.02)

    for process, _name in children:
        if process.pid not in return_codes:
            process.kill()
            sent_kill.add(process.pid)

    kill_deadline = time.monotonic() + SHUTDOWN_TIMEOUT_SECONDS
    while len(return_codes) < len(children) and time.monotonic() < kill_deadline:
        for process, _name in children:
            if process.pid in return_codes:
                continue
            return_code = process.poll()
            if return_code is not None:
                return_codes[process.pid] = return_code
        if len(return_codes) < len(children):
            time.sleep(0.02)

    # Close the boundary race where a child exits at the KILL deadline after
    # the loop's last poll. poll() also performs the final nonblocking reap.
    for process, _name in children:
        if process.pid not in return_codes:
            return_code = process.poll()
            if return_code is not None:
                return_codes[process.pid] = return_code

    unreaped = [
        f"{name} PID {process.pid}"
        for process, name in children
        if process.pid not in return_codes
    ]
    if unreaped:
        raise HarnessFailure(
            "children did not exit after bounded TERM/KILL: " + ", ".join(unreaped)
        )

    return [
        ChildShutdown(
            name=name,
            pid=process.pid,
            return_code=return_codes[process.pid],
            sent_term=process.pid in sent_term,
            sent_kill=process.pid in sent_kill,
            reaped=True,
        )
        for process, name in children
    ]


def validate_daemon_shutdown(result: ChildShutdown) -> None:
    expected = {0, -signal.SIGTERM}
    if result.sent_kill:
        expected.add(-signal.SIGKILL)
    if result.return_code not in expected:
        raise HarnessFailure(
            f"daemon PID {result.pid} exited abnormally with status {result.return_code}"
        )


def normalize_command_exit(return_code: int) -> int:
    if return_code < 0:
        return 128 + (-return_code)
    return return_code


def write_evidence(
    sandbox: Sandbox,
    executable: str,
    daemon: subprocess.Popen[bytes],
    reported: dict[str, str],
    control_metadata: os.stat_result,
    pass_environment: Sequence[str],
) -> None:
    command_env = command_environment(sandbox, daemon.pid, pass_environment)
    safe_command_env = {
        name: ("<explicit value omitted>" if name in pass_environment else value)
        for name, value in command_env.items()
    }
    document = {
        "daemon": {"executable": executable, "pid": daemon.pid},
        "isolation": {
            "kind": "configuration-and-session",
            "daemon_environment": base_environment(sandbox),
            "command_environment": safe_command_env,
            "explicitly_passed_environment_names": list(pass_environment),
            "reported_environment": reported,
        },
        "paths": {
            "scratch_root": str(sandbox.root),
            "control_directory": str(sandbox.control),
            "control_socket": str(sandbox.control / "control"),
            "login_keyring": str(sandbox.data / "keyrings" / "login.keyring"),
            "daemon_stdout": str(sandbox.stdout_log),
            "daemon_stderr": str(sandbox.stderr_log),
            "cleanup": str(sandbox.cleanup_log),
        },
        "readiness": {
            "initialization_stdout_eof": True,
            "daemon_alive": True,
            "control_socket_is_unix": True,
            "control_socket_owner_uid": control_metadata.st_uid,
            "external_sentinel_unchanged": True,
        },
        "redaction": {
            "command_argv_recorded": False,
            "command_output_captured": False,
            "protocol_frames_recorded": False,
        },
    }
    sandbox.evidence.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def write_cleanup(
    sandbox: Sandbox,
    command_return_code: int | None,
    children: Sequence[ChildShutdown],
    signal_number: int | None,
) -> None:
    document = {
        "command_return_code": command_return_code,
        "signal": signal.Signals(signal_number).name if signal_number is not None else None,
        "children": [asdict(child) for child in children],
    }
    sandbox.cleanup_log.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def run_command(
    command_argv: Sequence[str],
    *,
    keep_success: bool = False,
    pass_environment: Sequence[str] = (),
    _cleanup_started: Callable[[], None] | None = None,
) -> RunResult:
    """Run ``command_argv`` in a fresh daemon environment.

    The private ``_cleanup_started`` hook exists only for deterministic signal
    race regression testing. Production callers must leave it unset.
    """

    if "GMELL_HARNESS_ACTIVE" in os.environ:
        raise HarnessFailure(
            "nested lifecycle invocation is rejected (GMELL_HARNESS_ACTIVE is set)"
        )
    if not command_argv:
        raise HarnessFailure("no command was provided")

    old_umask = os.umask(0o077)
    signals = SignalLatch()
    signals.install()
    sandbox: Sandbox | None = None
    sentinel_path: Path | None = None
    sentinel_before: SentinelState | None = None
    daemon: subprocess.Popen[bytes] | None = None
    command: subprocess.Popen[bytes] | None = None
    stdout_stream: BinaryIO | None = None
    stderr_stream: BinaryIO | None = None
    command_return_code: int | None = None
    failure: BaseException | None = None
    cleanup_failure: BaseException | None = None
    shutdown: list[ChildShutdown] = []

    try:
        executable = shutil.which("gnome-keyring-daemon", path="/usr/bin:/bin")
        if executable is None:
            raise HarnessFailure("gnome-keyring-daemon was not found in /usr/bin:/bin")
        sandbox = create_sandbox()
        sentinel_path, sentinel_before = create_sentinel()
        signals.raise_if_pending()
        stdout_stream = sandbox.stdout_log.open("wb")
        stderr_stream = sandbox.stderr_log.open("wb")
        daemon = launch_daemon(executable, sandbox, stderr_stream)
        startup_deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        startup_output = wait_for_initialization_stdout_eof(
            daemon, stdout_stream, signals, startup_deadline
        )
        if daemon.stdout is not None:
            daemon.stdout.close()
        reported = parse_reported_environment(startup_output)
        if reported.get("GNOME_KEYRING_CONTROL") != str(sandbox.control):
            raise HarnessFailure("daemon did not report the selected control directory")
        validate_reported_paths(reported, sandbox.root)
        control_metadata = wait_for_control_socket(
            daemon, sandbox.control / "control", signals, startup_deadline
        )
        if read_sentinel(sentinel_path) != sentinel_before:
            raise HarnessFailure("external isolation sentinel changed before command launch")
        write_evidence(
            sandbox,
            executable,
            daemon,
            reported,
            control_metadata,
            pass_environment,
        )

        environment = command_environment(sandbox, daemon.pid, pass_environment)
        signals.raise_if_pending()
        command = subprocess.Popen(
            list(command_argv),
            env=environment,
            stdin=None,
            stdout=None,
            stderr=None,
            close_fds=True,
            start_new_session=True,
        )
        command_return_code = wait_for_command(command, daemon, signals)
    except BaseException as error:
        failure = error
    finally:
        if _cleanup_started is not None:
            try:
                _cleanup_started()
            except BaseException as error:
                cleanup_failure = error

        owned_children = [
            (process, name)
            for process, name in ((command, "command"), (daemon, "daemon"))
            if process is not None
        ]
        try:
            shutdown.extend(terminate_children(owned_children))
            daemon_shutdown = next(
                (child for child in shutdown if child.name == "daemon"), None
            )
            if daemon_shutdown is not None:
                validate_daemon_shutdown(daemon_shutdown)
        except BaseException as error:
            cleanup_failure = error

        if stdout_stream is not None:
            stdout_stream.close()
        if stderr_stream is not None:
            stderr_stream.close()
        if sandbox is not None:
            try:
                write_cleanup(sandbox, command_return_code, shutdown, signals.first)
            except BaseException as error:
                if cleanup_failure is None:
                    cleanup_failure = error

        if sentinel_path is not None and sentinel_before is not None:
            try:
                if read_sentinel(sentinel_path) != sentinel_before:
                    raise HarnessFailure(
                        "external isolation sentinel changed during harness execution"
                    )
            except BaseException as error:
                if cleanup_failure is None:
                    cleanup_failure = error

        # The latch remains installed until after every owned child is reaped
        # and cleanup evidence is durable. A first signal in this finally block
        # therefore cannot throw across or truncate teardown.
        signal_number = signals.first
        signals.restore()
        os.umask(old_umask)

    if cleanup_failure is not None:
        failure = HarnessFailure(f"owned cleanup failed: {cleanup_failure}")

    if signal_number is not None and failure is None:
        exit_code = 128 + signal_number
    elif isinstance(failure, SignalPending):
        if signal_number is None:
            failure = HarnessFailure("signal polling stopped without a latched signal")
            exit_code = HARNESS_FAILURE_EXIT
        else:
            failure = None
            exit_code = 128 + signal_number
    elif failure is not None:
        exit_code = HARNESS_FAILURE_EXIT
    elif command_return_code is None:
        failure = HarnessFailure("command produced no return code")
        exit_code = HARNESS_FAILURE_EXIT
    else:
        exit_code = normalize_command_exit(command_return_code)

    success = failure is None and signal_number is None and exit_code == 0
    retained = sandbox is not None and (keep_success or not success)
    if sandbox is not None and not retained:
        shutil.rmtree(sandbox.root)
    if sentinel_path is not None:
        sentinel_path.unlink(missing_ok=True)

    if failure is not None:
        if sandbox is not None:
            print(f"  retained scratch: {sandbox.root}", file=sys.stderr)
        if isinstance(failure, HarnessFailure):
            print(f"HARNESS FAILURE: {failure}", file=sys.stderr)
        else:
            raise failure
    elif signal_number is not None:
        if sandbox is not None:
            print(f"  retained scratch: {sandbox.root}", file=sys.stderr)
        print(
            f"HARNESS SIGNAL: received {signal.Signals(signal_number).name}; children reaped",
            file=sys.stderr,
        )
    elif exit_code != 0 and sandbox is not None:
        print(f"  retained scratch: {sandbox.root}", file=sys.stderr)
        print(f"COMMAND FAILURE: exit {exit_code}", file=sys.stderr)
    else:
        print("PASS: command completed in isolated gnome-keyring harness")
        if retained and sandbox is not None:
            print(f"  artifacts: {sandbox.root}")

    return RunResult(exit_code, sandbox.root if sandbox is not None else None, retained)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""command environment (assembled from an empty map):
  HOME, TMPDIR, XDG_{RUNTIME,DATA,CONFIG,CACHE,STATE}_HOME
  DBUS_{SESSION,SYSTEM}_BUS_ADDRESS (unreachable private paths)
  GNOME_KEYRING_CONTROL (directory containing the control socket)
  GMELL_HARNESS_ACTIVE=1
  GMELL_HARNESS_ROOT, GMELL_HARNESS_CONTROL_DIR,
  GMELL_HARNESS_CONTROL_SOCKET, GMELL_HARNESS_DAEMON_PID,
  GMELL_HARNESS_DAEMON_{STDOUT,STDERR}, GMELL_HARNESS_EVIDENCE,
  GMELL_HARNESS_CLEANUP

exit semantics:
  command status       propagated unchanged
  command signal       128 + signal number
  HUP/INT/TERM          owned teardown, then 128 + first signal number
  harness failure      125 (usage errors remain argparse status 2)

Nonzero command, signal, and harness failures retain the mode-0700 scratch
root and print its path. A set GMELL_HARNESS_ACTIVE rejects nesting before
allocating a scratch root. Command stdout/stderr remain caller-owned streams.
""",
    )
    parser.add_argument(
        "--keep-success",
        action="store_true",
        help="retain the private scratch directory after command success",
    )
    parser.add_argument(
        "--pass-env",
        action="append",
        default=[],
        metavar="NAME",
        help="copy one non-protected caller variable into the command environment",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="command after --")
    arguments = parser.parse_args()
    if arguments.command and arguments.command[0] == "--":
        arguments.command = arguments.command[1:]
    if not arguments.command:
        parser.error("a command is required after --")
    return arguments


def main() -> int:
    arguments = parse_args()
    try:
        result = run_command(
            arguments.command,
            keep_success=arguments.keep_success,
            pass_environment=arguments.pass_env,
        )
    except HarnessFailure as error:
        print(f"HARNESS FAILURE: {error}", file=sys.stderr)
        return HARNESS_FAILURE_EXIT
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
