#!/usr/bin/env python3
"""Run one command with a private dbus-broker and gnome-keyring-daemon.

This is the D-Bus sibling of ``lifecycle.py``. It preserves the same private
HOME/XDG/storage boundary, but gives the daemon and command an explicit private
session bus instead of an unreachable one::

    dev/harness/broker.py -- command arg ...
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Sequence

import lifecycle


BUS_NAME = "org.freedesktop.DBus"
BUS_PATH = "/org/freedesktop/DBus"
KEYRING_NAMES = ("org.gnome.keyring", "org.freedesktop.secrets")
JOURNAL_SOCKET = Path("/run/systemd/journal/socket")
SYSTEMD_RUNTIME = Path("/run/systemd/system")
SYSTEM_BUS_SOCKET = Path("/run/dbus/system_bus_socket")
# systemd-socket-activate 261 exec_process() passes only this whitelist (plus
# LISTEN_* variables and explicit --setenv values) to the activated service;
# every other variable in the activator's environment is stripped.
SOCKET_ACTIVATE_ENVIRONMENT_WHITELIST = (
    "TERM",
    "COLORTERM",
    "NO_COLOR",
    "PATH",
    "USER",
    "HOME",
)
GDBUS_CALL_TIMEOUT_SECONDS = 1.0

BUS_CONFIG = """<busconfig>
  <type>session</type>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
    <allow own="*"/>
  </policy>
</busconfig>
"""


@dataclass(frozen=True)
class BrokerPaths:
    socket: Path
    config: Path
    launcher_stdout: Path
    launcher_stderr: Path


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    parent_pid: int
    executable: str
    start_time_ticks: int


@dataclass
class OwnedBroker:
    launcher: subprocess.Popen[bytes]
    broker: ProcessIdentity
    broker_pidfd: int
    listener_kernel_inode: int
    launcher_listener_fds: list[int]
    broker_listener_fds: list[int]
    activatable_names: list[str]


@dataclass(frozen=True)
class BrokerShutdown:
    name: str
    pid: int
    return_code: None
    sent_term: bool
    sent_kill: bool
    reaped: bool
    reaper: str


@dataclass(frozen=True)
class BusReadiness:
    name_owners: dict[str, str]
    owner_pid: int


def broker_paths(sandbox: lifecycle.Sandbox) -> BrokerPaths:
    return BrokerPaths(
        socket=sandbox.root / "bus",
        config=sandbox.root / "bus.conf",
        launcher_stdout=sandbox.root / "broker-launcher.stdout.log",
        launcher_stderr=sandbox.root / "broker-launcher.stderr.log",
    )


def private_bus_environment(
    sandbox: lifecycle.Sandbox, paths: BrokerPaths
) -> dict[str, str]:
    environment = lifecycle.base_environment(sandbox)
    environment["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={paths.socket}"
    return environment


def launcher_environment(
    sandbox: lifecycle.Sandbox, paths: BrokerPaths
) -> dict[str, str]:
    # This environment reaches systemd-socket-activate, not dbus-broker-launch
    # itself: the activator execs the service with only the whitelist above
    # (plus LISTEN_*), so every other variable here - including the
    # unreachable-scratch DBUS_SYSTEM_BUS_ADDRESS inherited from the base
    # environment - is stripped before the launcher runs. dbus-broker-launch
    # --scope=system then opens its libsystemd controller with
    # sd_bus_open_system(), which connects to the real system bus socket on
    # this host, and calls org.freedesktop.systemd1.Manager.Subscribe there
    # even though this config declares zero activatable services. Redirecting
    # the system-bus address here would be dead configuration that falsely
    # suggests controller isolation: launcher contact with host systemd and
    # the system bus is an accepted host dependency, recorded in evidence.
    return private_bus_environment(sandbox, paths)


def command_environment(
    sandbox: lifecycle.Sandbox,
    paths: BrokerPaths,
    daemon_pid: int,
    owned_broker: OwnedBroker,
    pass_environment: Sequence[str],
) -> dict[str, str]:
    environment = lifecycle.command_environment(
        sandbox, daemon_pid, pass_environment
    )
    environment.update(
        {
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path={paths.socket}",
            "GMELL_HARNESS_MODE": "private-broker",
            "GMELL_HARNESS_BUS_SOCKET": str(paths.socket),
            "GMELL_HARNESS_BUS_CONFIG": str(paths.config),
            "GMELL_HARNESS_BROKER_LAUNCHER_PID": str(owned_broker.launcher.pid),
            "GMELL_HARNESS_BROKER_PID": str(owned_broker.broker.pid),
            "GMELL_HARNESS_BROKER_STDOUT": str(paths.launcher_stdout),
            "GMELL_HARNESS_BROKER_STDERR": str(paths.launcher_stderr),
        }
    )
    return environment


def require_host_dependencies() -> dict[str, str]:
    executables: dict[str, str] = {}
    for name in (
        "systemd-socket-activate",
        "dbus-broker-launch",
        "gnome-keyring-daemon",
        "gdbus",
    ):
        executable = shutil.which(name, path="/usr/bin:/bin")
        if executable is None:
            raise lifecycle.HarnessFailure(f"{name} was not found in /usr/bin:/bin")
        executables[name] = executable

    try:
        journal_metadata = JOURNAL_SOCKET.stat()
    except FileNotFoundError as error:
        raise lifecycle.HarnessFailure(
            f"dbus-broker-launch requires the host journal socket at {JOURNAL_SOCKET}"
        ) from error
    if not stat.S_ISSOCK(journal_metadata.st_mode):
        raise lifecycle.HarnessFailure(
            f"host journal endpoint is not a socket: {JOURNAL_SOCKET}"
        )
    # dbus-broker-launch --scope=system opens its libsystemd controller with
    # sd_bus_open_system(), which eagerly connects to the host system bus:
    # without it the launcher exits before readiness. The harness's
    # DBUS_SYSTEM_BUS_ADDRESS never steers this connection (see
    # launcher_environment), so the system bus is a hard host dependency.
    try:
        system_bus_metadata = SYSTEM_BUS_SOCKET.stat()
    except FileNotFoundError as error:
        raise lifecycle.HarnessFailure(
            "dbus-broker-launch --scope=system requires the host system bus at "
            f"{SYSTEM_BUS_SOCKET} for its libsystemd controller connection"
        ) from error
    if not stat.S_ISSOCK(system_bus_metadata.st_mode):
        raise lifecycle.HarnessFailure(
            f"host system bus endpoint is not a socket: {SYSTEM_BUS_SOCKET}"
        )
    if not SYSTEMD_RUNTIME.is_dir():
        raise lifecycle.HarnessFailure(
            f"dbus-broker-launch --scope=system requires a running host systemd at {SYSTEMD_RUNTIME}"
        )
    return executables


def write_bus_config(paths: BrokerPaths) -> None:
    paths.config.write_text(BUS_CONFIG, encoding="utf-8")
    if any(token in BUS_CONFIG for token in ("<servicedir>", "<standard_session_servicedirs", "<include")):
        raise lifecycle.HarnessFailure("private bus config unexpectedly enables service activation")


def launch_broker(
    executables: dict[str, str],
    sandbox: lifecycle.Sandbox,
    paths: BrokerPaths,
    stdout_stream: BinaryIO,
    stderr_stream: BinaryIO,
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            executables["systemd-socket-activate"],
            f"--listen={paths.socket}",
            executables["dbus-broker-launch"],
            "--scope=system",
            f"--config-file={paths.config}",
        ],
        env=launcher_environment(sandbox, paths),
        stdin=subprocess.DEVNULL,
        stdout=stdout_stream,
        stderr=stderr_stream,
        close_fds=True,
        start_new_session=True,
    )


def wait_for_bus_socket(
    launcher: subprocess.Popen[bytes],
    path: Path,
    signals: lifecycle.SignalLatch,
    deadline: float,
) -> os.stat_result:
    while True:
        signals.raise_if_pending()
        return_code = launcher.poll()
        if return_code is not None:
            raise lifecycle.HarnessFailure(
                f"broker socket activator exited before readiness with status {return_code}"
            )
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if time.monotonic() >= deadline:
                raise lifecycle.HarnessFailure("timed out waiting for private bus socket") from None
            time.sleep(0.02)
            continue
        if not stat.S_ISSOCK(metadata.st_mode):
            raise lifecycle.HarnessFailure(f"private bus path is not a socket: {path}")
        if metadata.st_uid != os.geteuid():
            raise lifecycle.HarnessFailure(
                f"private bus socket UID {metadata.st_uid} does not match effective UID {os.geteuid()}"
            )
        # systemd-socket-activate creates the pathname as 0644 on this host,
        # despite the supervisor's umask. Tighten it before the first client
        # connection; the containing root is already mode 0700.
        path.chmod(0o600)
        metadata = path.lstat()
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise lifecycle.HarnessFailure(
                f"private bus socket permissions are too broad: {stat.S_IMODE(metadata.st_mode):04o}"
            )
        return metadata


def gdbus_call(
    executable: str,
    address: str,
    method: str,
    environment: dict[str, str],
    arguments: Sequence[str] = (),
    destination: str = BUS_NAME,
    object_path: str = BUS_PATH,
) -> str:
    result = subprocess.run(
        [
            executable,
            "call",
            f"--address={address}",
            f"--dest={destination}",
            f"--object-path={object_path}",
            f"--method={method}",
            *arguments,
        ],
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=GDBUS_CALL_TIMEOUT_SECONDS,
        check=False,
    )
    if result.returncode != 0:
        diagnostic = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "no diagnostic"
        raise lifecycle.HarnessFailure(f"private bus call {method} failed: {diagnostic}")
    return result.stdout.strip()


def wait_for_bus_answer(
    launcher: subprocess.Popen[bytes],
    gdbus: str,
    sandbox: lifecycle.Sandbox,
    paths: BrokerPaths,
    signals: lifecycle.SignalLatch,
    deadline: float,
) -> None:
    address = f"unix:path={paths.socket}"
    latest_error: BaseException | None = None
    while time.monotonic() < deadline:
        signals.raise_if_pending()
        return_code = launcher.poll()
        if return_code is not None:
            raise lifecycle.HarnessFailure(
                f"dbus-broker-launch exited before readiness with status {return_code}"
            )
        try:
            output = gdbus_call(
                gdbus,
                address,
                f"{BUS_NAME}.ListNames",
                private_bus_environment(sandbox, paths),
            )
            if BUS_NAME not in output:
                raise lifecycle.HarnessFailure("private bus ListNames response omitted the bus name")
            return
        except (lifecycle.HarnessFailure, subprocess.TimeoutExpired) as error:
            latest_error = error
            time.sleep(0.02)
    raise lifecycle.HarnessFailure(
        f"timed out waiting for a private bus method response: {latest_error}"
    )


def process_identity(pid: int, expected_parent: int, expected_name: str) -> ProcessIdentity:
    proc = Path(f"/proc/{pid}")
    try:
        executable = str((proc / "exe").readlink())
        status = (proc / "status").read_text(encoding="utf-8")
        raw_stat = (proc / "stat").read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise lifecycle.HarnessFailure(f"process PID {pid} vanished during identity proof") from error
    parent_match = re.search(r"^PPid:\s+(\d+)$", status, re.MULTILINE)
    if parent_match is None or int(parent_match.group(1)) != expected_parent:
        raise lifecycle.HarnessFailure(
            f"process PID {pid} is not a child of expected PID {expected_parent}"
        )
    if Path(executable).name != expected_name:
        raise lifecycle.HarnessFailure(
            f"process PID {pid} executable is {executable}, expected {expected_name}"
        )
    after_command = raw_stat.rsplit(")", 1)[1].split()
    return ProcessIdentity(
        pid=pid,
        parent_pid=expected_parent,
        executable=executable,
        start_time_ticks=int(after_command[19]),
    )


def direct_children(pid: int) -> list[int]:
    path = Path(f"/proc/{pid}/task/{pid}/children")
    try:
        return [int(value) for value in path.read_text(encoding="utf-8").split()]
    except FileNotFoundError:
        return []


def wait_for_broker_child(
    launcher: subprocess.Popen[bytes],
    signals: lifecycle.SignalLatch,
    deadline: float,
) -> tuple[ProcessIdentity, int]:
    while time.monotonic() < deadline:
        signals.raise_if_pending()
        return_code = launcher.poll()
        if return_code is not None:
            raise lifecycle.HarnessFailure(
                f"dbus-broker-launch exited before child proof with status {return_code}"
            )
        children = direct_children(launcher.pid)
        if len(children) == 1:
            identity = process_identity(children[0], launcher.pid, "dbus-broker")
            try:
                return identity, os.pidfd_open(identity.pid)
            except ProcessLookupError:
                continue
        if len(children) > 1:
            raise lifecycle.HarnessFailure(
                f"dbus-broker-launch has unexpected direct children: {children}"
            )
        time.sleep(0.02)
    raise lifecycle.HarnessFailure("timed out waiting for exact dbus-broker child")


def launcher_identity(launcher: subprocess.Popen[bytes]) -> ProcessIdentity:
    return process_identity(launcher.pid, os.getpid(), "dbus-broker-launch")


def unix_listener_inode(path: Path) -> int:
    for line in Path("/proc/net/unix").read_text(encoding="utf-8").splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 8 and fields[7] == str(path):
            return int(fields[6])
    raise lifecycle.HarnessFailure(f"private listener was not present in /proc/net/unix: {path}")


def process_socket_fds(pid: int, kernel_inode: int) -> list[int]:
    expected = f"socket:[{kernel_inode}]"
    descriptors: list[int] = []
    directory = Path(f"/proc/{pid}/fd")
    try:
        entries = list(directory.iterdir())
    except FileNotFoundError as error:
        raise lifecycle.HarnessFailure(f"process PID {pid} vanished during FD proof") from error
    for entry in entries:
        try:
            target = str(entry.readlink())
        except FileNotFoundError:
            continue
        if target == expected:
            descriptors.append(int(entry.name))
    return sorted(descriptors)


def prove_broker_ready(
    launcher: subprocess.Popen[bytes],
    executables: dict[str, str],
    sandbox: lifecycle.Sandbox,
    paths: BrokerPaths,
    signals: lifecycle.SignalLatch,
) -> tuple[OwnedBroker, os.stat_result]:
    deadline = time.monotonic() + lifecycle.STARTUP_TIMEOUT_SECONDS
    socket_metadata = wait_for_bus_socket(launcher, paths.socket, signals, deadline)
    wait_for_bus_answer(
        launcher, executables["gdbus"], sandbox, paths, signals, deadline
    )
    activatable_names = parse_string_array(
        gdbus_call(
            executables["gdbus"],
            f"unix:path={paths.socket}",
            f"{BUS_NAME}.ListActivatableNames",
            private_bus_environment(sandbox, paths),
        ),
        "ListActivatableNames",
    )
    unexpected_activatable = set(activatable_names) - {BUS_NAME}
    if unexpected_activatable:
        raise lifecycle.HarnessFailure(
            "private bus loaded unexpected activatable services: "
            + ", ".join(sorted(unexpected_activatable))
        )
    launcher_identity(launcher)
    identity, pidfd = wait_for_broker_child(launcher, signals, deadline)
    try:
        listener_inode = unix_listener_inode(paths.socket)
        launcher_fds = process_socket_fds(launcher.pid, listener_inode)
        broker_fds = process_socket_fds(identity.pid, listener_inode)
        if not launcher_fds or not broker_fds:
            raise lifecycle.HarnessFailure(
                "listener FD ownership was not shared by dbus-broker-launch and dbus-broker"
            )
    except BaseException:
        # Keep exact ownership: the pidfd acquired above still refers to the
        # broker child, so only this function may close it, on every path.
        os.close(pidfd)
        raise
    return (
        OwnedBroker(
            launcher=launcher,
            broker=identity,
            broker_pidfd=pidfd,
            listener_kernel_inode=listener_inode,
            launcher_listener_fds=launcher_fds,
            broker_listener_fds=broker_fds,
            activatable_names=activatable_names,
        ),
        socket_metadata,
    )


def launch_daemon(
    executable: str,
    sandbox: lifecycle.Sandbox,
    paths: BrokerPaths,
    stderr_stream: BinaryIO,
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            executable,
            "--foreground",
            "--components=secrets",
            "--control-directory",
            str(sandbox.control),
        ],
        env=private_bus_environment(sandbox, paths),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=stderr_stream,
        close_fds=True,
        start_new_session=True,
    )


def parse_single_string(output: str, method: str) -> str:
    try:
        values = ast.literal_eval(output)
    except (SyntaxError, ValueError) as error:
        raise lifecycle.HarnessFailure(f"could not parse {method} response") from error
    if not isinstance(values, tuple) or len(values) != 1 or not isinstance(values[0], str):
        raise lifecycle.HarnessFailure(f"unexpected {method} response shape")
    return values[0]


def parse_string_array(output: str, method: str) -> list[str]:
    try:
        values = ast.literal_eval(output)
    except (SyntaxError, ValueError) as error:
        raise lifecycle.HarnessFailure(f"could not parse {method} response") from error
    if (
        not isinstance(values, tuple)
        or len(values) != 1
        or not isinstance(values[0], list)
        or any(not isinstance(value, str) for value in values[0])
    ):
        raise lifecycle.HarnessFailure(f"unexpected {method} response shape")
    return values[0]


def wait_for_keyring_names(
    daemon: subprocess.Popen[bytes],
    owned_broker: OwnedBroker,
    gdbus: str,
    sandbox: lifecycle.Sandbox,
    paths: BrokerPaths,
    signals: lifecycle.SignalLatch,
) -> BusReadiness:
    deadline = time.monotonic() + lifecycle.STARTUP_TIMEOUT_SECONDS
    address = f"unix:path={paths.socket}"
    latest_error: BaseException | None = None
    while time.monotonic() < deadline:
        signals.raise_if_pending()
        if daemon.poll() is not None:
            raise lifecycle.HarnessFailure(
                f"daemon exited before bus-name readiness with status {daemon.returncode}"
            )
        if owned_broker.launcher.poll() is not None:
            raise lifecycle.HarnessFailure(
                "dbus-broker-launch exited before daemon bus-name readiness"
            )
        if pidfd_exited(owned_broker.broker_pidfd):
            raise lifecycle.HarnessFailure("dbus-broker exited before daemon bus-name readiness")
        try:
            owners = {
                name: parse_single_string(
                    gdbus_call(
                        gdbus,
                        address,
                        f"{BUS_NAME}.GetNameOwner",
                        private_bus_environment(sandbox, paths),
                        (name,),
                    ),
                    "GetNameOwner",
                )
                for name in KEYRING_NAMES
            }
            if len(set(owners.values())) != 1:
                raise lifecycle.HarnessFailure(
                    f"keyring bus names have different owners: {owners}"
                )
            owner = next(iter(owners.values()))
            pid_output = gdbus_call(
                gdbus,
                address,
                f"{BUS_NAME}.GetConnectionUnixProcessID",
                private_bus_environment(sandbox, paths),
                (owner,),
            )
            match = re.fullmatch(r"\(uint32 (\d+),\)", pid_output)
            if match is None:
                raise lifecycle.HarnessFailure(
                    "unexpected GetConnectionUnixProcessID response shape"
                )
            owner_pid = int(match.group(1))
            if owner_pid != daemon.pid:
                raise lifecycle.HarnessFailure(
                    f"keyring bus names belong to PID {owner_pid}, expected daemon PID {daemon.pid}"
                )
            return BusReadiness(owners, owner_pid)
        except (lifecycle.HarnessFailure, subprocess.TimeoutExpired) as error:
            latest_error = error
            time.sleep(0.02)
    raise lifecycle.HarnessFailure(
        f"timed out proving keyring bus-name ownership: {latest_error}"
    )


def pidfd_exited(pidfd: int) -> bool:
    readable, _, _ = select.select([pidfd], [], [], 0)
    return bool(readable)


def wait_for_command(
    command: subprocess.Popen[bytes],
    daemon: subprocess.Popen[bytes],
    owned_broker: OwnedBroker,
    signals: lifecycle.SignalLatch,
) -> int:
    while True:
        signals.raise_if_pending()
        daemon_code = daemon.poll()
        if daemon_code is not None:
            raise lifecycle.HarnessFailure(
                f"daemon exited with status {daemon_code} while the command was running"
            )
        launcher_code = owned_broker.launcher.poll()
        if launcher_code is not None:
            raise lifecycle.HarnessFailure(
                f"dbus-broker-launch exited with status {launcher_code} while the command was running"
            )
        if pidfd_exited(owned_broker.broker_pidfd):
            raise lifecycle.HarnessFailure("dbus-broker exited while the command was running")
        return_code = command.poll()
        if return_code is not None:
            return return_code
        time.sleep(0.05)


def wait_pidfd(pidfd: int, timeout: float) -> bool:
    readable, _, _ = select.select([pidfd], [], [], timeout)
    return bool(readable)


def process_identity_matches(pid: int, start_time_ticks: int) -> bool:
    """Whether /proc/<pid> still refers to the exact recorded process.

    Start ticks from /proc/<pid>/stat (field 22) stay stable for the life of
    the process, including while it is a zombie. A missing /proc entry, or an
    entry whose start ticks differ, therefore means the recorded process is
    gone from this PID - for an exited process that it was reaped (possibly
    followed by PID reuse), never that it is still running.
    """
    try:
        raw_stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except (FileNotFoundError, ProcessLookupError):
        # ENOENT for a fully gone PID, ESRCH for the transient procfs
        # window while the entry disappears underneath the open.
        return False
    after_command = raw_stat.rsplit(")", 1)[1].split()
    return int(after_command[19]) == start_time_ticks


def wait_broker_reaped(identity: ProcessIdentity, timeout: float) -> None:
    """Require the exited broker's launcher to reap it, bounded.

    The caller has already observed exit through the broker pidfd, so a
    matching /proc entry here can only be an unreaped zombie. If the PID was
    reused after reaping, the start ticks differ and the wait succeeds: only a
    reaped process can have its PID reused. The check is one-directional - it
    can fail loudly on a stalled launcher, never pass on an unreaped broker.
    """
    deadline = time.monotonic() + timeout
    while process_identity_matches(identity.pid, identity.start_time_ticks):
        if time.monotonic() >= deadline:
            raise lifecycle.HarnessFailure(
                f"dbus-broker PID {identity.pid} exited but was not reaped by its launcher"
            )
        time.sleep(0.02)


def stop_owned_broker(
    owned: OwnedBroker,
) -> tuple[lifecycle.ChildShutdown, BrokerShutdown]:
    broker_was_live = not pidfd_exited(owned.broker_pidfd)
    broker_sent_term = False
    broker_sent_kill = False
    if broker_was_live:
        signal.pidfd_send_signal(owned.broker_pidfd, signal.SIGTERM)
        broker_sent_term = True
    if not wait_pidfd(owned.broker_pidfd, lifecycle.SHUTDOWN_TIMEOUT_SECONDS):
        signal.pidfd_send_signal(owned.broker_pidfd, signal.SIGKILL)
        broker_sent_kill = True
        if not wait_pidfd(owned.broker_pidfd, lifecycle.SHUTDOWN_TIMEOUT_SECONDS):
            raise lifecycle.HarnessFailure(
                f"dbus-broker PID {owned.broker.pid} did not exit after bounded TERM/KILL"
            )

    # dbus-broker-launch is the broker's real parent. Give it the opportunity
    # to reap that exact child before terminating/reaping the launcher itself.
    wait_broker_reaped(owned.broker, lifecycle.SHUTDOWN_TIMEOUT_SECONDS)

    # A launcher whose broker died by signal always exits by itself once it
    # has reaped the child (launcher_on_child_exit exits the event loop with
    # EXIT_FAILURE). Wait briefly for that self-exit so the launcher's own
    # status is observed instead of racing a TERM into its exit path.
    if (
        broker_sent_kill or not broker_was_live
    ) and owned.launcher.poll() is None:
        deadline = time.monotonic() + lifecycle.SHUTDOWN_TIMEOUT_SECONDS
        while owned.launcher.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)

    launcher_shutdown = lifecycle.terminate_children(
        ((owned.launcher, "broker-launcher"),)
    )[0]
    expected_launcher_codes = {0, -signal.SIGTERM, -signal.SIGKILL}
    if broker_sent_kill or not broker_was_live:
        # dbus-broker-launch 37 launcher_on_child_exit() exits with
        # EXIT_FAILURE (1) whenever its broker child died by a signal instead
        # of exiting normally. Both cases here are harness-supervised teardown,
        # not launcher faults: the broker was KILLed by this function after
        # TERM did not suffice, or had already exited before teardown began.
        expected_launcher_codes.add(1)
    if launcher_shutdown.return_code not in expected_launcher_codes:
        raise lifecycle.HarnessFailure(
            "dbus-broker-launch exited abnormally with status "
            f"{launcher_shutdown.return_code}"
        )
    broker_shutdown = BrokerShutdown(
        name="broker",
        pid=owned.broker.pid,
        return_code=None,
        sent_term=broker_sent_term,
        sent_kill=broker_sent_kill,
        reaped=True,
        reaper=f"broker-launcher PID {owned.launcher.pid}",
    )
    return launcher_shutdown, broker_shutdown


def validate_broker_daemon_shutdown(
    result: lifecycle.ChildShutdown, failure_already_recorded: bool
) -> None:
    """Validate daemon teardown without masking an already-recorded failure.

    Identical to ``lifecycle.validate_daemon_shutdown`` except that a daemon
    which exited before harness-initiated teardown is only a harness failure
    when nothing else already failed: when the broker or launcher died under
    the command, the daemon's private bus disappears and the daemon exits by
    itself (observed status 0), and the primary failure is the actionable
    report. A TERMed daemon is always status-checked strictly.
    """
    if not result.sent_term and failure_already_recorded:
        return
    lifecycle.validate_daemon_shutdown(result)


def discover_partial_broker(
    launcher: subprocess.Popen[bytes],
) -> OwnedBroker | None:
    """Adopt an exact broker child when startup failed before readiness.

    Before the first connection the direct child is still
    systemd-socket-activate and has no broker. After activation it execs into
    dbus-broker-launch and has exactly one dbus-broker child. This recovery
    keeps failure teardown exact even if a later identity/FD proof failed.
    """

    if launcher.poll() is not None:
        return None
    children = direct_children(launcher.pid)
    if not children:
        return None
    if len(children) != 1:
        raise lifecycle.HarnessFailure(
            f"broker startup left unexpected direct children: {children}"
        )
    identity = process_identity(children[0], launcher.pid, "dbus-broker")
    return OwnedBroker(
        launcher=launcher,
        broker=identity,
        broker_pidfd=os.pidfd_open(identity.pid),
        listener_kernel_inode=0,
        launcher_listener_fds=[],
        broker_listener_fds=[],
        activatable_names=[],
    )


def write_evidence(
    sandbox: lifecycle.Sandbox,
    paths: BrokerPaths,
    executables: dict[str, str],
    owned_broker: OwnedBroker,
    daemon: subprocess.Popen[bytes],
    ready_daemon: lifecycle.ReadyDaemon,
    socket_metadata: os.stat_result,
    bus_readiness: BusReadiness,
    pass_environment: Sequence[str],
) -> None:
    environment = command_environment(
        sandbox, paths, daemon.pid, owned_broker, pass_environment
    )
    safe_environment = {
        name: ("<explicit value omitted>" if name in pass_environment else value)
        for name, value in environment.items()
    }
    launcher = launcher_identity(owned_broker.launcher)
    document = {
        "mode": "private-broker",
        "isolation": {
            "kind": "configuration-and-session",
            "daemon_environment": private_bus_environment(sandbox, paths),
            "launcher_environment": {
                "passed_to_systemd_socket_activate": launcher_environment(
                    sandbox, paths
                ),
                "reaches_dbus_broker_launch": (
                    "only the systemd-socket-activate 261 exec_process whitelist: "
                    + ", ".join(SOCKET_ACTIVATE_ENVIRONMENT_WHITELIST)
                    + ", plus LISTEN_* variables"
                ),
                "dbus_system_bus_address_reaches_launcher": False,
            },
            "command_environment": safe_environment,
            "explicitly_passed_environment_names": list(pass_environment),
            "host_service_activation_directories": [],
            "activatable_names": owned_broker.activatable_names,
            "no_host_service_activation_proven_by": [
                "zero service directories in the private bus config",
                "ListActivatableNames returned only org.freedesktop.DBus",
            ],
            "launcher_controller": {
                "connection": (
                    "libsystemd sd_bus_open_system (dbus-broker-launch 37 "
                    "launcher_connect)"
                ),
                "system_bus_socket": str(SYSTEM_BUS_SOCKET),
                "isolated_by_harness": False,
                "note": (
                    "the launcher calls org.freedesktop.systemd1.Manager.Subscribe "
                    "on the host system bus regardless of service definitions; "
                    "DBUS_SYSTEM_BUS_ADDRESS cannot redirect it because "
                    "systemd-socket-activate strips it before exec"
                ),
            },
            "host_dependencies": {
                "systemd_socket_activation_protocol": True,
                "scope": "system",
                "journal_socket": str(JOURNAL_SOCKET),
                "systemd_runtime": str(SYSTEMD_RUNTIME),
                "launcher_controller_system_bus": str(SYSTEM_BUS_SOCKET),
                "total_host_independence": False,
            },
        },
        "processes": {
            "broker_launcher": asdict(launcher),
            "broker": asdict(owned_broker.broker),
            "daemon": {
                "pid": daemon.pid,
                "executable": executables["gnome-keyring-daemon"],
            },
        },
        "paths": {
            "scratch_root": str(sandbox.root),
            "bus_socket": str(paths.socket),
            "bus_config": str(paths.config),
            "control_directory": str(sandbox.control),
            "control_socket": str(sandbox.control / "control"),
            "login_keyring": str(sandbox.data / "keyrings" / "login.keyring"),
            "daemon_stdout": str(sandbox.stdout_log),
            "daemon_stderr": str(sandbox.stderr_log),
            "broker_stdout": str(paths.launcher_stdout),
            "broker_stderr": str(paths.launcher_stderr),
            "cleanup": str(sandbox.cleanup_log),
        },
        "readiness": {
            "socket_activation_inherited": True,
            "private_bus_answered": True,
            "bus_socket_owner_uid": socket_metadata.st_uid,
            "bus_socket_mode": f"{stat.S_IMODE(socket_metadata.st_mode):04o}",
            "listener_kernel_inode": owned_broker.listener_kernel_inode,
            "listener_fd_holders": {
                "broker_launcher": owned_broker.launcher_listener_fds,
                "broker": owned_broker.broker_listener_fds,
            },
            "daemon_initialization_stdout_eof": True,
            "daemon_alive": True,
            "control_socket_is_unix": True,
            "control_socket_owner_uid": ready_daemon.control_metadata.st_uid,
            "name_owners": bus_readiness.name_owners,
            "name_owner_pid": bus_readiness.owner_pid,
            "external_sentinel_unchanged": True,
        },
        "redaction": {
            "command_argv_recorded": False,
            "command_output_captured": False,
            "protocol_secrets_recorded": False,
        },
    }
    sandbox.evidence.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def write_cleanup(
    sandbox: lifecycle.Sandbox,
    command_return_code: int | None,
    children: Sequence[lifecycle.ChildShutdown | BrokerShutdown],
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
) -> lifecycle.RunResult:
    if "GMELL_HARNESS_ACTIVE" in os.environ:
        raise lifecycle.HarnessFailure(
            "nested lifecycle invocation is rejected (GMELL_HARNESS_ACTIVE is set)"
        )
    if not command_argv:
        raise lifecycle.HarnessFailure("no command was provided")

    old_umask = os.umask(0o077)
    signals = lifecycle.SignalLatch()
    signals.install()
    sandbox: lifecycle.Sandbox | None = None
    paths: BrokerPaths | None = None
    sentinel_path: Path | None = None
    sentinel_before: lifecycle.SentinelState | None = None
    launcher: subprocess.Popen[bytes] | None = None
    owned_broker: OwnedBroker | None = None
    daemon: subprocess.Popen[bytes] | None = None
    command: subprocess.Popen[bytes] | None = None
    streams: list[BinaryIO] = []
    command_return_code: int | None = None
    failure: BaseException | None = None
    cleanup_failure: BaseException | None = None
    shutdown: list[lifecycle.ChildShutdown | BrokerShutdown] = []
    signal_number: int | None = None

    try:
        executables = require_host_dependencies()
        sandbox = lifecycle.create_sandbox()
        paths = broker_paths(sandbox)
        write_bus_config(paths)
        sentinel_path, sentinel_before = lifecycle.create_sentinel()
        signals.raise_if_pending()

        launcher_stdout = paths.launcher_stdout.open("wb")
        launcher_stderr = paths.launcher_stderr.open("wb")
        daemon_stdout = sandbox.stdout_log.open("wb")
        daemon_stderr = sandbox.stderr_log.open("wb")
        streams.extend((launcher_stdout, launcher_stderr, daemon_stdout, daemon_stderr))

        launcher = launch_broker(
            executables,
            sandbox,
            paths,
            launcher_stdout,
            launcher_stderr,
        )
        owned_broker, socket_metadata = prove_broker_ready(
            launcher, executables, sandbox, paths, signals
        )
        daemon = launch_daemon(
            executables["gnome-keyring-daemon"], sandbox, paths, daemon_stderr
        )
        ready_daemon = lifecycle.prove_daemon_ready(
            daemon, sandbox, daemon_stdout, signals
        )
        bus_readiness = wait_for_keyring_names(
            daemon, owned_broker, executables["gdbus"], sandbox, paths, signals
        )
        if lifecycle.read_sentinel(sentinel_path) != sentinel_before:
            raise lifecycle.HarnessFailure(
                "external isolation sentinel changed before command launch"
            )
        write_evidence(
            sandbox,
            paths,
            executables,
            owned_broker,
            daemon,
            ready_daemon,
            socket_metadata,
            bus_readiness,
            pass_environment,
        )

        environment = command_environment(
            sandbox, paths, daemon.pid, owned_broker, pass_environment
        )
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
        command_return_code = wait_for_command(
            command, daemon, owned_broker, signals
        )
    except BaseException as error:
        failure = error
    finally:
        if _cleanup_started is not None:
            try:
                _cleanup_started()
            except BaseException as error:
                cleanup_failure = error

        direct_children = [
            (process, name)
            for process, name in ((command, "command"), (daemon, "daemon"))
            if process is not None
        ]
        try:
            direct_shutdown = lifecycle.terminate_children(direct_children)
            shutdown.extend(direct_shutdown)
            daemon_shutdown = next(
                (child for child in direct_shutdown if child.name == "daemon"), None
            )
            if daemon_shutdown is not None:
                validate_broker_daemon_shutdown(daemon_shutdown, failure is not None)
        except BaseException as error:
            cleanup_failure = error

        if owned_broker is not None:
            try:
                launcher_shutdown, broker_shutdown = stop_owned_broker(owned_broker)
                shutdown.extend((launcher_shutdown, broker_shutdown))
            except BaseException as error:
                if cleanup_failure is None:
                    cleanup_failure = error
            finally:
                os.close(owned_broker.broker_pidfd)
        elif launcher is not None:
            try:
                partial_broker = discover_partial_broker(launcher)
                if partial_broker is None:
                    shutdown.extend(
                        lifecycle.terminate_children(((launcher, "broker-launcher"),))
                    )
                else:
                    try:
                        launcher_shutdown, broker_shutdown = stop_owned_broker(
                            partial_broker
                        )
                        shutdown.extend((launcher_shutdown, broker_shutdown))
                    finally:
                        os.close(partial_broker.broker_pidfd)
            except BaseException as error:
                if cleanup_failure is None:
                    cleanup_failure = error

        for stream in streams:
            stream.close()
        if sandbox is not None:
            try:
                write_cleanup(sandbox, command_return_code, shutdown, signals.first)
            except BaseException as error:
                if cleanup_failure is None:
                    cleanup_failure = error

        if sentinel_path is not None and sentinel_before is not None:
            try:
                if lifecycle.read_sentinel(sentinel_path) != sentinel_before:
                    raise lifecycle.HarnessFailure(
                        "external isolation sentinel changed during harness execution"
                    )
            except BaseException as error:
                if cleanup_failure is None:
                    cleanup_failure = error

        signal_number = signals.first
        signals.restore()
        os.umask(old_umask)

    if cleanup_failure is not None:
        failure = lifecycle.HarnessFailure(f"owned cleanup failed: {cleanup_failure}")

    if signal_number is not None and failure is None:
        exit_code = 128 + signal_number
    elif isinstance(failure, lifecycle.SignalPending):
        if signal_number is None:
            failure = lifecycle.HarnessFailure(
                "signal polling stopped without a latched signal"
            )
            exit_code = lifecycle.HARNESS_FAILURE_EXIT
        else:
            failure = None
            exit_code = 128 + signal_number
    elif failure is not None:
        exit_code = lifecycle.HARNESS_FAILURE_EXIT
    elif command_return_code is None:
        failure = lifecycle.HarnessFailure("command produced no return code")
        exit_code = lifecycle.HARNESS_FAILURE_EXIT
    else:
        exit_code = lifecycle.normalize_command_exit(command_return_code)

    success = failure is None and signal_number is None and exit_code == 0
    retained = sandbox is not None and (keep_success or not success)
    if sandbox is not None and not retained:
        shutil.rmtree(sandbox.root)
    if sentinel_path is not None:
        sentinel_path.unlink(missing_ok=True)

    if failure is not None:
        if sandbox is not None:
            print(f"  retained scratch: {sandbox.root}", file=sys.stderr)
        if isinstance(failure, lifecycle.HarnessFailure):
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
        print("PASS: command completed in isolated private-broker harness")
        if retained and sandbox is not None:
            print(f"  artifacts: {sandbox.root}")

    return lifecycle.RunResult(
        exit_code, sandbox.root if sandbox is not None else None, retained
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""private-broker additions to the lifecycle command environment:
  DBUS_SESSION_BUS_ADDRESS=unix:path=<root>/bus
  GMELL_HARNESS_MODE=private-broker
  GMELL_HARNESS_BUS_SOCKET, GMELL_HARNESS_BUS_CONFIG
  GMELL_HARNESS_BROKER_{LAUNCHER_,}PID
  GMELL_HARNESS_BROKER_{STDOUT,STDERR}

DBUS_SYSTEM_BUS_ADDRESS remains an unreachable scratch path for the daemon and
command. The minimal bus config has no service directories, so no host D-Bus
service activation exists; only this harness manually launches
gnome-keyring-daemon. The launcher itself is exec'd by systemd-socket-activate
with a minimal whitelisted environment: its libsystemd controller connects to
the real system bus and subscribes to the host systemd manager, so host
systemd/journald/system-bus facilities are required dependencies. This is
configuration and session isolation, not total host independence.

Exit, retention, --pass-env, nesting, and stream semantics match lifecycle.py.
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
    except lifecycle.HarnessFailure as error:
        print(f"HARNESS FAILURE: {error}", file=sys.stderr)
        return lifecycle.HARNESS_FAILURE_EXIT
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
