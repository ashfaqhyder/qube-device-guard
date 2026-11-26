"""Verify an intact key backup and reject damaged or untrusted copies."""

import base64
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

from pqcrypto.sign import ml_dsa_65

from device_keys import enrol_device, initialize_registry, rotate_device_key
from key_backup import (
    BackupVerificationError,
    create_key_backup,
    load_verified_key_backup,
)


def expect_rejection(path, trusted_public_key):
    try:
        load_verified_key_backup(path, trusted_public_key)
    except BackupVerificationError as exc:
        assert str(exc) == "Backup signature verification failed", str(exc)
        return

    raise AssertionError("An unverified backup returned key material")


def main():
    old_public, _ = ml_dsa_65.generate_keypair()
    current_public, _ = ml_dsa_65.generate_keypair()
    backup_public, backup_secret = ml_dsa_65.generate_keypair()
    unrelated_public, _ = ml_dsa_65.generate_keypair()

    with TemporaryDirectory() as state_dir:
        folder = Path(state_dir)
        backup_path = folder / "keys.json"
        damaged_path = folder / "keys-damaged.json"

        with closing(sqlite3.connect(folder / "state.sqlite3")) as connection:
            with connection:
                initialize_registry(connection)
                enrol_device(connection, "maya", old_public)
                rotated = rotate_device_key(connection, "maya", 1, current_public)
                assert rotated

            create_key_backup(connection, backup_path, backup_secret)

        recovered = load_verified_key_backup(backup_path, backup_public)
        assert recovered == [("maya", 2, current_public)]
        print("PASS: verified backup returned Maya's committed version 2 public key")

        envelope = json.loads(backup_path.read_text(encoding="utf-8"))
        damaged_payload = bytearray(base64.b64decode(envelope["payload"]))
        damaged_payload[-1] ^= 1
        envelope["payload"] = base64.b64encode(damaged_payload).decode("ascii")
        damaged_path.write_text(json.dumps(envelope), encoding="utf-8")

        expect_rejection(damaged_path, backup_public)
        print("PASS: damaged backup was rejected before key records were returned")

        expect_rejection(backup_path, unrelated_public)
        print("PASS: intact backup was rejected with an unrelated verification key")


if __name__ == "__main__":
    main()