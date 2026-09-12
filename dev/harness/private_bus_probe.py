#!/usr/bin/env python3
"""Probe a plain Secret Service session and GNOME's private interface."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path


SERVICE = "org.freedesktop.secrets"
SERVICE_PATH = "/org/freedesktop/secrets"
SERVICE_INTERFACE = "org.freedesktop.Secret.Service"
COLLECTION_INTERFACE = "org.freedesktop.Secret.Collection"
PROPERTIES_INTERFACE = "org.freedesktop.DBus.Properties"
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


def property_get(object_path: str, interface: str, name: str) -> str:
    return run(
        "call",
        f"--address={os.environ['DBUS_SESSION_BUS_ADDRESS']}",
        f"--dest={SERVICE}",
        f"--object-path={object_path}",
        f"--method={PROPERTIES_INTERFACE}.Get",
        interface,
        name,
    ).strip()


def measure_collections() -> tuple[list[str], dict[str, bool]]:
    """Read the advertised collection set and each collection's Locked state.

    Both are standard Secret Service property reads: no collection is created,
    locked, unlocked, or otherwise mutated. A collection that disappears
    between the two reads fails loudly instead of being silently skipped.
    """
    output = property_get(SERVICE_PATH, SERVICE_INTERFACE, "Collections")
    inner = output[output.index("[") + 1 : output.rindex("]")]
    paths = re.findall(r"objectpath '([^']+)'", inner)
    locked: dict[str, bool] = {}
    for path in paths:
        state = property_get(path, COLLECTION_INTERFACE, "Locked")
        match = re.fullmatch(r"\(<(true|false)>,\)", state)
        if match is None:
            raise RuntimeError(f"unexpected Locked response shape for {path}: {state}")
        locked[path] = match.group(1) == "true"
    return paths, locked


def main() -> int:
    if os.environ.get("GMELL_HARNESS_MODE") != "private-broker":
        raise RuntimeError("private_bus_probe.py must run inside broker.py")
    root = Path(os.environ["GMELL_HARNESS_ROOT"])
    socket = Path(os.environ["GMELL_HARNESS_BUS_SOCKET"])
    expected_address = f"unix:path={socket}"
    if os.environ.get("DBUS_SESSION_BUS_ADDRESS") != expected_address:
        raise RuntimeError("command did not receive the explicit private bus address")
    socket.resolve(strict=True).relative_to(root.resolve(strict=True))

    collections_before, locked_before = measure_collections()

    session = run(
        "call",
        f"--address={expected_address}",
        f"--dest={SERVICE}",
        f"--object-path={SERVICE_PATH}",
        f"--method={SERVICE_INTERFACE}.OpenSession",
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

    collections_after, locked_after = measure_collections()

    if collections_after != collections_before:
        raise RuntimeError(
            "collection set changed across OpenSession and introspection: "
            f"{collections_before} -> {collections_after}"
        )
    if locked_after != locked_before:
        raise RuntimeError(
            "collection lock state changed across OpenSession and introspection: "
            f"{locked_before} -> {locked_after}"
        )

    (root / "private-bus-probe.json").write_text(
        json.dumps(
            {
                "plain_session_opened": True,
                "private_interface_introspectable": True,
                "private_interface": PRIVATE_INTERFACE,
                "collections_before": collections_before,
                "locked_before": locked_before,
                "collections_after": collections_after,
                "locked_after": locked_after,
                "collections_unchanged": True,
                "locked_state_unchanged": True,
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
