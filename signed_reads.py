"""Authenticated reads for the local Track 4 mock service."""

import json
import sqlite3
from contextlib import closing

from pqcrypto.sign import ml_dsa_65

from device_keys import active_key
from team_app import can_read, load_state


def signed_payload(actor, asset, request_id, key_version):
    """Produce the same bytes on the client and the service."""
    return json.dumps(
        ["qube-device-guard:read:v1", actor, asset, request_id, key_version],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def signed_read(database, actor, asset, request_id, key_version, signature):
    with closing(sqlite3.connect(database)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            state = load_state(connection)
            registered = active_key(connection, actor)

            if not can_read(state, actor, asset) or registered is None:
                return {"decision": "deny"}

            active_version, public_key = registered
            if key_version != active_version:
                return {"decision": "deny"}

            message = signed_payload(actor, asset, request_id, key_version)
            if not ml_dsa_65.verify(public_key, message, signature):
                return {"decision": "deny"}

            recorded = connection.execute(
                """
                INSERT INTO read_audit (request_id, decision) VALUES (?, 'allow')
                ON CONFLICT(request_id) DO NOTHING
                """,
                (request_id,),
            )
            if recorded.rowcount != 1:
                return {"decision": "deny"}

            return {"decision": "allow", "body": state["contents"][asset]}