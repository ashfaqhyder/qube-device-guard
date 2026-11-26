"""Restore missing public keys from a current, verified backup."""

import base64
import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

from pqcrypto.sign import ml_dsa_65

from device_keys import active_key, enrol_device, initialize_registry, rotate_device_key
from key_backup import (
    BackupVerificationError,
    create_key_backup,
    load_verified_key_backup,
)
from team_app import can_read, load_state, setup


def key_identity(version, public_key):
    return version, hashlib.sha256(public_key).hexdigest()


def restore_missing_keys(database, backup_path, signer_public_key, trusted_keys):
    records = load_verified_key_backup(backup_path, signer_public_key)
    backup_keys = {
        actor: key_identity(version, public_key)
        for actor, version, public_key in records
    }
    if len(backup_keys) != len(records) or backup_keys != trusted_keys:
        raise BackupVerificationError("Backup does not match the trusted key registry")

    restored = 0
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            load_state(connection)

            for actor, version, public_key in records:
                existing = active_key(connection, actor)
                if existing is None:
                    connection.execute(
                        """
                        INSERT INTO device_keys (actor, version, public_key)
                        VALUES (?, ?, ?)
                        """,
                        (actor, version, public_key),
                    )
                    restored += 1
                elif existing != (version, public_key):
                    raise BackupVerificationError("Live key conflicts with verified backup")

    return restored


def expect_rejection(database, backup_path, signer_public_key, trusted_keys, reason):
    try:
        restore_missing_keys(database, backup_path, signer_public_key, trusted_keys)
    except BackupVerificationError as exc:
        assert str(exc) == reason, str(exc)
        return
    raise AssertionError("Restore accepted a backup that should have been rejected")


def main():
    old_public, _ = ml_dsa_65.generate_keypair()
    current_public, _ = ml_dsa_65.generate_keypair()
    lost_public, _ = ml_dsa_65.generate_keypair()
    signer_public, signer_secret = ml_dsa_65.generate_keypair()

    with TemporaryDirectory() as directory:
        folder = Path(directory)
        database = folder / "state.sqlite3"
        stale_backup = folder / "stale.json"
        current_backup = folder / "current.json"
        damaged_backup = folder / "damaged.json"

        with closing(sqlite3.connect(database)) as connection:
            with connection:
                setup(connection, {
                    "owners": {"brief": "maya", "lost-file": "arun"},
                    "contents": {"brief": "demo note", "lost-file": "peer note"},
                    "disabled": ["arun"],
                })
                initialize_registry(connection)
                enrol_device(connection, "maya", old_public)
                enrol_device(connection, "arun", lost_public)

            create_key_backup(connection, stale_backup, signer_secret)

            with connection:
                rotated = rotate_device_key(connection, "maya", 1, current_public)
                assert rotated
            create_key_backup(connection, current_backup, signer_secret)

            # Simulate saving a trusted checkpoint before a registry row is lost.
            trusted_keys = {
                actor: key_identity(version, public_key)
                for actor, version, public_key in connection.execute(
                    "SELECT actor, version, public_key FROM device_keys"
                )
            }
            with connection:
                connection.execute("DELETE FROM device_keys WHERE actor = ?", ("maya",))

        # Prove that the stale backup is authentic before testing freshness.
        stale_records = load_verified_key_backup(stale_backup, signer_public)
        assert ("maya", 1, old_public) in stale_records
        expect_rejection(
            database, stale_backup, signer_public, trusted_keys,
            "Backup does not match the trusted key registry",
        )
        print("PASS: authentic version 1 backup was rejected as stale")

        envelope = json.loads(current_backup.read_text(encoding="utf-8"))
        payload = bytearray(base64.b64decode(envelope["payload"]))
        payload[-1] ^= 1
        envelope["payload"] = base64.b64encode(payload).decode("ascii")
        damaged_backup.write_text(json.dumps(envelope), encoding="utf-8")
        expect_rejection(
            database, damaged_backup, signer_public, trusted_keys,
            "Backup signature verification failed",
        )

        with closing(sqlite3.connect(database)) as connection:
            assert active_key(connection, "maya") is None
            assert not can_read(load_state(connection), "arun", "lost-file")
        print("PASS: damaged backup was rejected and neither rejection changed live state")

        restored = restore_missing_keys(
            database, current_backup, signer_public, trusted_keys
        )
        assert restored == 1
        with closing(sqlite3.connect(database)) as connection:
            assert active_key(connection, "maya") == (2, current_public)
            assert active_key(connection, "arun") == (1, lost_public)
            state = load_state(connection)
            assert can_read(state, "maya", "brief")
            assert state["contents"]["brief"] == "demo note"
            assert not can_read(state, "arun", "lost-file")
        print("PASS: verified version 2 key was restored and Arun stayed revoked")

        repeated = restore_missing_keys(
            database, current_backup, signer_public, trusted_keys
        )
        assert repeated == 0
        print("PASS: repeating the restore made no additional changes")


if __name__ == "__main__":
    main()