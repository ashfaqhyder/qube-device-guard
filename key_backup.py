"""Create and verify signed snapshots of the device public-key registry."""

import base64
import binascii
import json
from pathlib import Path

from pqcrypto.sign import ml_dsa_65


class BackupVerificationError(ValueError):
    """The backup could not be verified safely."""


def create_key_backup(connection, backup_path, signing_key):
    rows = connection.execute(
        "SELECT actor, version, public_key FROM device_keys ORDER BY actor"
    ).fetchall()

    payload = json.dumps(
        {
            "format": "qube-device-key-backup-v1",
            "records": [
                {
                    "actor": actor,
                    "version": version,
                    "public_key": base64.b64encode(public_key).decode("ascii"),
                }
                for actor, version, public_key in rows
            ],
        },
        separators=(",", ":"),
    ).encode("utf-8")

    signature = ml_dsa_65.sign(signing_key, payload)
    envelope = {
        "payload": base64.b64encode(payload).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    Path(backup_path).write_text(json.dumps(envelope), encoding="utf-8")


def load_verified_key_backup(backup_path, trusted_public_key):
    try:
        envelope = json.loads(Path(backup_path).read_text(encoding="utf-8"))
        payload = base64.b64decode(envelope["payload"], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
    except (OSError, ValueError, TypeError, KeyError, binascii.Error) as exc:
        raise BackupVerificationError("Backup could not be read") from exc

    if not ml_dsa_65.verify(trusted_public_key, payload, signature):
        raise BackupVerificationError("Backup signature verification failed")

    try:
        snapshot = json.loads(payload)
        if snapshot["format"] != "qube-device-key-backup-v1":
            raise ValueError("Unsupported backup format")
        return [
            (
                record["actor"],
                record["version"],
                base64.b64decode(record["public_key"], validate=True),
            )
            for record in snapshot["records"]
        ]
    except (ValueError, TypeError, KeyError, binascii.Error) as exc:
        raise BackupVerificationError("Verified backup payload is invalid") from exc