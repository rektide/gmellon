#!/usr/bin/env python3
"""Probe a plain Secret Service session and GNOME's private interface."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


SERVICE = "org.freedesktop.secrets"
SERVICE_PATH = "/org/freedesktop/secrets"
PRIVATE_INTERFACE = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface"
PRIVATE_ENVIRONMENT_NAMES = (
    "HOME",
    "XDG_RUNTIME_DIR",
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "TMPDIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "DBUS_SYSTEM_BUS_ADDRESS",
    "PATH",
    "LANG",
    "LC_ALL",
)


def run(*arguments: str) -> str:
    environment = {name: os.environ[name] for name in PRIVATE_ENVIRONMENT_NAMES}
    result = subprocess.run(
        ["/usr/bin/gdbus", *arguments],
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    if result.returncode != 0:
        diagnostic = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "no diagnostic"
        raise RuntimeError(f"gdbus probe failed: {diagnostic}")
    return result.stdout


def main() -> int:
    if os.environ.get("GMELL_HARNESS_MODE") != "private-broker":
        raise RuntimeError("private_bus_probe.py must run inside broker.py")
    root = Path(os.environ["GMELL_HARNESS_ROOT"])
    socket = Path(os.environ["GMELL_HARNESS_BUS_SOCKET"])
    expected_address = f"unix:path={socket}"
    if os.environ.get("DBUS_SESSION_BUS_ADDRESS") != expected_address:
        raise RuntimeError("command did not receive the explicit private bus address")
    socket.resolve(strict=True).relative_to(root.resolve(strict=True))

    session = run(
        "call",
        f"--address={expected_address}",
        f"--dest={SERVICE}",
        f"--object-path={SERVICE_PATH}",
        "--method=org.freedesktop.Secret.Service.OpenSession",
        "plain",
        "<''>",
    )
    if "/org/freedesktop/secrets/session/" not in session:
        raise RuntimeError("plain OpenSession response did not contain a session path")

    introspection = run(
        "introspect",
        f"--address={expected_address}",
        f"--dest={SERVICE}",
        f"--object-path={SERVICE_PATH}",
    )
    required_symbols = (
        PRIVATE_INTERFACE,
        "UnlockWithMasterPassword",
        "ChangeWithMasterPassword",
    )
    missing = [symbol for symbol in required_symbols if symbol not in introspection]
    if missing:
        raise RuntimeError(f"private interface introspection omitted: {', '.join(missing)}")

    (root / "private-bus-probe.json").write_text(
        json.dumps(
            {
                "plain_session_opened": True,
                "private_interface_introspectable": True,
                "private_interface": PRIVATE_INTERFACE,
                "password_method_called": False,
                "collection_lock_state_changed": False,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print("PASS: private bus opened a plain session and exposed the GNOME interface")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
