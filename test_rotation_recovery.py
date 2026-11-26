"""Test key rotation recovery on both sides of the SQLite commit boundary."""

import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

from pqcrypto.sign import ml_dsa_65

from device_keys import (
    active_key,
    enrol_device,
    initialize_registry,
    rotate_device_key,
)
from test_protected_read import call_adapter
from test_signed_rotation import probe


def interrupt_rotation(database, proposed_key_file, phase):
    proposed_key = proposed_key_file.read_bytes()
    connection = sqlite3.connect(database)
    connection.execute("BEGIN IMMEDIATE")

    if not rotate_device_key(connection, "maya", 1, proposed_key):
        raise RuntimeError("Rotation did not update Maya's key")

    if phase == "before-commit":
        os._exit(23)

    if phase == "after-commit":
        connection.commit()
        os._exit(24)

    raise ValueError(f"Unknown interruption phase: {phase}")


def check_recovery(phase):
    old_public, old_secret = ml_dsa_65.generate_keypair()
    new_public, new_secret = ml_dsa_65.generate_keypair()
    lost_public, lost_secret = ml_dsa_65.generate_keypair()
    committed = phase == "after-commit"

    with TemporaryDirectory() as state_dir:
        database = Path(state_dir) / "state.sqlite3"
        proposed_key_file = Path(state_dir) / "proposed-public-key.bin"
        proposed_key_file.write_bytes(new_public)

        assert call_adapter(state_dir, {
            "op": "setup",
            "owners": {"brief": "maya", "lost-file": "arun"},
            "contents": {"brief": "demo note", "lost-file": "peer note"},
            "disabled": [],
            "key_material": "synthetic-only",
        }) == {"ready": True}

        with closing(sqlite3.connect(database)) as connection:
            with connection:
                initialize_registry(connection)
                enrol_device(connection, "maya", old_public)
                enrol_device(connection, "arun", lost_public)

        with ProcessPoolExecutor(max_workers=1) as worker:
            assert probe(
                worker, database, "arun", "lost-file",
                "arun-before-revocation", 1, lost_secret,
            ) == {"decision": "allow", "body": "peer note"}

        call_adapter(state_dir, {"op": "revoke", "actor": "arun"})

        interrupted = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--interrupt",
                phase,
                str(database),
                str(proposed_key_file),
            ],
            timeout=15,
        )
        expected_exit = 24 if committed else 23
        assert interrupted.returncode == expected_exit, (
            f"{phase}: expected child exit {expected_exit}, "
            f"got {interrupted.returncode}"
        )
        print(f"PASS [{phase}]: child reached the intended interruption point")

        if committed:
            expected_version, expected_public = 2, new_public
            active_secret, denied_secret = new_secret, old_secret
            denied_version = 1
        else:
            expected_version, expected_public = 1, old_public
            active_secret, denied_secret = old_secret, new_secret
            denied_version = 2

        with closing(sqlite3.connect(database)) as connection:
            recovered = active_key(connection, "maya")
            assert recovered == (expected_version, expected_public), (
                f"{phase}: expected key version {expected_version}, "
                f"got {recovered[0] if recovered else 'no key'}"
            )

            if committed:
                with connection:
                    retried = rotate_device_key(
                        connection, "maya", 1, new_public
                    )
                assert retried is False
                assert active_key(connection, "maya") == (2, new_public)
                print("PASS [after-commit]: stale retry left version 2 active")

        print(f"PASS [{phase}]: recovered key version {expected_version}")

        with ProcessPoolExecutor(max_workers=1) as restarted_worker:
            assert probe(
                restarted_worker, database, "maya", "brief",
                "maya-active-key-after-restart", expected_version, active_secret,
            ) == {"decision": "allow", "body": "demo note"}
            assert probe(
                restarted_worker, database, "maya", "brief",
                "maya-inactive-key-after-restart", denied_version, denied_secret,
            ) == {"decision": "deny"}
            assert probe(
                restarted_worker, database, "arun", "lost-file",
                "arun-after-restart", 1, lost_secret,
            ) == {"decision": "deny"}

        print(f"PASS [{phase}]: active key read the committed file")
        print(f"PASS [{phase}]: inactive key denied and Arun stayed revoked")


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--interrupt":
        interrupt_rotation(
            Path(sys.argv[3]), Path(sys.argv[4]), sys.argv[2]
        )
    else:
        check_recovery("before-commit")
        check_recovery("after-commit")