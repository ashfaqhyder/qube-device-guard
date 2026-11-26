"""Re-enrol a mock owner with a replacement device after revocation."""

import json
import secrets
import sqlite3
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
from key_event_log import append_event, initialize_log, verify_log
from operator_workflow import revoke_with_audit
from team_app import load_state, setup
from test_signed_rotation import probe


def reenrol_device(
    database, audit_key, *, operator, actor, expected_version, replacement_key
):
    """Return the committed audit head, or None when re-enrolment is declined."""
    if not isinstance(replacement_key, bytes):
        return None
    if len(replacement_key) != ml_dsa_65.PUBLIC_KEY_SIZE:
        return None

    with closing(sqlite3.connect(database)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            state = load_state(connection)
            if actor not in state["disabled"]:
                return None

            # The registry rejects stale versions and reuse of the current key.
            if not rotate_device_key(
                connection, actor, expected_version, replacement_key
            ):
                return None

            state["disabled"].remove(actor)
            connection.execute(
                "UPDATE app_state SET data = ? WHERE id = 1",
                (json.dumps(state),),
            )
            head = append_event(
                connection, audit_key,
                actor=operator, action="reenrol", subject=actor,
            )
        return head


def main():
    audit_key = secrets.token_bytes(32)
    lost_public, lost_secret = ml_dsa_65.generate_keypair()
    replacement_public, replacement_secret = ml_dsa_65.generate_keypair()
    peer_public, peer_secret = ml_dsa_65.generate_keypair()
    operator = "operator-1"

    with TemporaryDirectory() as directory:
        database = Path(directory) / "state.sqlite3"
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
                enrol_device(connection, "maya", lost_public)
                enrol_device(connection, "arun", peer_public)

        allow_maya = {"decision": "allow", "body": "demo note"}
        allow_arun = {"decision": "allow", "body": "peer note"}
        deny = {"decision": "deny"}

        with ProcessPoolExecutor(max_workers=1) as node_a, \
                ProcessPoolExecutor(max_workers=1) as node_b:
            workers = {"A": node_a, "B": node_b}

            for name, worker in workers.items():
                assert probe(
                    worker, database, "maya", "brief",
                    f"{name}-before-loss", 1, lost_secret,
                ) == allow_maya

            revoked_head = revoke_with_audit(
                database, audit_key, operator=operator, actor="maya",
                note="synthetic device-loss report",
            )
            assert revoked_head is not None

            for name, worker in workers.items():
                assert probe(
                    worker, database, "maya", "brief",
                    f"{name}-revoked", 1, lost_secret,
                ) == deny
                assert probe(
                    worker, database, "arun", "peer-file",
                    f"{name}-peer-during-revocation", 1, peer_secret,
                ) == allow_arun
            print("PASS: both workers denied the lost device and preserved peer access")

            refused = reenrol_device(
                database, audit_key, operator=operator, actor="maya",
                expected_version=1, replacement_key=lost_public,
            )
            assert refused is None
            with closing(sqlite3.connect(database)) as connection:
                assert "maya" in load_state(connection)["disabled"]
                assert verify_log(connection, audit_key, revoked_head)
            print("PASS: reusing the lost key was refused and Maya stayed revoked")

            reenrolled_head = reenrol_device(
                database, audit_key, operator=operator, actor="maya",
                expected_version=1, replacement_key=replacement_public,
            )
            assert reenrolled_head is not None

            for name, worker in workers.items():
                assert probe(
                    worker, database, "maya", "brief",
                    f"{name}-replacement", 2, replacement_secret,
                ) == allow_maya
                assert probe(
                    worker, database, "maya", "brief",
                    f"{name}-lost-credential", 1, lost_secret,
                ) == deny
                assert probe(
                    worker, database, "maya", "brief",
                    f"{name}-lost-key-claims-v2", 2, lost_secret,
                ) == deny
                assert probe(
                    worker, database, "arun", "peer-file",
                    f"{name}-peer-after-reenrolment", 1, peer_secret,
                ) == allow_arun
                print(f"PASS: {name} accepted the replacement, denied the lost key, and kept peer access")

        with closing(sqlite3.connect(database)) as connection:
            assert active_key(connection, "maya") == (2, replacement_public)
            assert "maya" not in load_state(connection)["disabled"]
            assert verify_log(connection, audit_key, reenrolled_head)
            rows = connection.execute(
                "SELECT event_json FROM key_events ORDER BY sequence"
            ).fetchall()
            events = [json.loads(row[0]) for row in rows]
            assert [
                (event["actor"], event["action"], event["subject"])
                for event in events
            ] == [
                (operator, "revoke", "maya"),
                (operator, "reenrol", "maya"),
            ]
        print("PASS: the replacement key and both verifiable audit events persisted")


if __name__ == "__main__":
    main()