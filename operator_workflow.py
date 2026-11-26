"""Local Track 4 operator actions with transactional key-event logging."""

import json
import secrets
import sqlite3
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
from key_event_log import append_event, initialize_log, verify_log
from team_app import load_state, revoke, setup


def rotate_with_audit(
    database, audit_key, *, operator, actor, expected_version, new_public_key
):
    """Return the committed log head, or None if the rotation was declined."""
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            if actor in load_state(connection)["disabled"]:
                return None

            if not rotate_device_key(
                connection, actor, expected_version, new_public_key
            ):
                return None

            head = append_event(
                connection, audit_key,
                actor=operator, action="rotate", subject=actor,
            )
        return head


def revoke_with_audit(database, audit_key, *, operator, actor, note=""):
    """Return the committed log head, or None if already revoked."""
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            if actor in load_state(connection)["disabled"]:
                return None

            revoke(connection, {"actor": actor})
            head = append_event(
                connection, audit_key,
                actor=operator, action="revoke", subject=actor, note=note,
            )
        return head


def main():
    audit_key = secrets.token_bytes(32)
    old_public, _ = ml_dsa_65.generate_keypair()
    new_public, _ = ml_dsa_65.generate_keypair()
    candidate_public, _ = ml_dsa_65.generate_keypair()
    operator = "operator-1"
    note = 'reported lost\n{"actor":"maya","action":"enrol"}'

    with TemporaryDirectory() as state_dir:
        database = Path(state_dir) / "state.sqlite3"

        with closing(sqlite3.connect(database)) as connection:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                setup(connection, {
                    "owners": {"brief": "maya", "peer-file": "arun"},
                    "contents": {"brief": "demo note", "peer-file": "peer note"},
                    "disabled": [],
                })
                initialize_registry(connection)
                initialize_log(connection)
                enrol_device(connection, "maya", old_public)

        rotation_head = rotate_with_audit(
            database, audit_key, operator=operator, actor="maya",
            expected_version=1, new_public_key=new_public,
        )
        assert rotation_head is not None

        with closing(sqlite3.connect(database)) as connection:
            assert active_key(connection, "maya") == (2, new_public)
            assert verify_log(connection, audit_key, rotation_head)
        print("PASS: rotation and its audit event committed together")

        trusted_head = revoke_with_audit(
            database, audit_key, operator=operator, actor="arun", note=note,
        )
        assert trusted_head is not None

        with closing(sqlite3.connect(database)) as connection:
            assert "arun" in load_state(connection)["disabled"]
            assert verify_log(connection, audit_key, trusted_head)

            rows = connection.execute(
                "SELECT event_json FROM key_events ORDER BY sequence"
            ).fetchall()
            events = [json.loads(row[0]) for row in rows]
            assert len(events) == 2
            assert [
                (event["actor"], event["action"], event["subject"])
                for event in events
            ] == [
                (operator, "rotate", "maya"),
                (operator, "revoke", "arun"),
            ]
            assert events[1]["note"] == note

            # Test-only fault in the synthetic database.
            with connection:
                connection.execute("""
                    CREATE TRIGGER fail_audit_insert
                    BEFORE INSERT ON key_events
                    BEGIN
                        SELECT RAISE(ABORT, 'simulated audit write failure');
                    END
                """)

        print("PASS: revocation is verifiable and the note stayed in one event")

        try:
            rotate_with_audit(
                database, audit_key, operator=operator, actor="maya",
                expected_version=2, new_public_key=candidate_public,
            )
        except sqlite3.IntegrityError as exc:
            assert str(exc) == "simulated audit write failure"
        else:
            raise AssertionError("Expected the simulated audit failure")

        with closing(sqlite3.connect(database)) as connection:
            assert active_key(connection, "maya") == (2, new_public)
            assert "arun" in load_state(connection)["disabled"]
            assert verify_log(connection, audit_key, trusted_head)

        print("PASS: failed audit write rolled back the attempted key change")
        print("PASS: the prior revocation and trusted log head remained valid")


if __name__ == "__main__":
    main()