"""Authenticated key-event log and local integrity self-test."""

import hmac
import json
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone


EMPTY_HEAD = bytes(32)


def initialize_log(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS key_events (
            sequence INTEGER PRIMARY KEY,
            event_json TEXT NOT NULL,
            tag BLOB NOT NULL
        )
    """)


def event_tag(audit_key, sequence, previous_tag, event_json):
    message = (
        b"qube-key-event-v1\x00"
        + sequence.to_bytes(8, "big")
        + previous_tag
        + event_json.encode("utf-8")
    )
    return hmac.digest(audit_key, message, "sha256")


def append_event(connection, audit_key, *, actor, action, subject, note=""):
    """Append within the caller's write transaction and return the new head."""
    previous = connection.execute("""
        SELECT sequence, tag FROM key_events ORDER BY sequence DESC LIMIT 1
    """).fetchone()

    sequence = previous[0] + 1 if previous else 1
    previous_tag = previous[1] if previous else EMPTY_HEAD
    event_json = json.dumps(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "action": action,
            "subject": subject,
            "note": note,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )

    tag = event_tag(audit_key, sequence, previous_tag, event_json)
    connection.execute(
        "INSERT INTO key_events (sequence, event_json, tag) VALUES (?, ?, ?)",
        (sequence, event_json, tag),
    )
    return tag


def verify_log(connection, audit_key, trusted_head):
    """Verify every row and compare the final tag with a trusted checkpoint."""
    previous_tag = EMPTY_HEAD
    rows = connection.execute("""
        SELECT sequence, event_json, tag FROM key_events ORDER BY sequence
    """)

    for expected_sequence, (sequence, event_json, stored_tag) in enumerate(rows, 1):
        if sequence != expected_sequence:
            return False

        expected_tag = event_tag(audit_key, sequence, previous_tag, event_json)
        if not hmac.compare_digest(stored_tag, expected_tag):
            return False

        previous_tag = stored_tag

    return hmac.compare_digest(previous_tag, trusted_head)


def main():
    audit_key = secrets.token_bytes(32)
    note = 'lost device\n{"actor":"maya","action":"enrol"}'

    with closing(sqlite3.connect(":memory:")) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            initialize_log(connection)
            append_event(
                connection, audit_key,
                actor="operator-1", action="rotate", subject="maya",
            )
            trusted_head = append_event(
                connection, audit_key,
                actor="operator-1", action="revoke", subject="arun", note=note,
            )

        assert verify_log(connection, audit_key, trusted_head)
        print("PASS: intact key-event log verified")

        rows = connection.execute(
            "SELECT event_json FROM key_events ORDER BY sequence"
        ).fetchall()
        assert len(rows) == 2
        revoke_event = json.loads(rows[1][0])
        assert revoke_event["actor"] == "operator-1"
        assert revoke_event["action"] == "revoke"
        assert revoke_event["note"] == note
        print("PASS: multiline text stayed in one event and preserved the actor")

        altered = json.loads(rows[0][0])
        altered["actor"] = "maya"
        connection.execute(
            "UPDATE key_events SET event_json = ? WHERE sequence = 1",
            (json.dumps(altered),),
        )
        assert not verify_log(connection, audit_key, trusted_head)
        connection.rollback()
        assert verify_log(connection, audit_key, trusted_head)
        print("PASS: changing a recorded actor was detected")

        connection.execute("DELETE FROM key_events WHERE sequence = 2")
        assert not verify_log(connection, audit_key, trusted_head)
        connection.rollback()
        print("PASS: deleting the final event was detected")


if __name__ == "__main__":
    main()