"""Application logic for the Track 4 protected-resource adapter."""

import json
import os
import sqlite3
import tempfile
import base64
import binascii
import hmac
from contextlib import closing
from pathlib import Path
from pqcrypto.kem import ml_kem_768


def state_path():
    configured_dir = os.environ.get("TRACK4_STATE_DIR")
    if configured_dir:
        state_dir = Path(configured_dir)
    else:
        state_dir = Path(tempfile.gettempdir()) / "qube-device-guard"

    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir / "state.sqlite3"


def setup(connection, request):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS app_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            data TEXT NOT NULL
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS read_audit (
            request_id TEXT PRIMARY KEY,
            decision TEXT NOT NULL
        )
    """)
    initial_state = {
        "owners": request["owners"],
        "contents": request["contents"],
        "disabled": request["disabled"],
    }
    connection.execute(
        """
        INSERT INTO app_state (id, data) VALUES (1, ?)
        ON CONFLICT(id) DO UPDATE SET data = excluded.data
        """,
        (json.dumps(initial_state),),
    )
    connection.execute("DELETE FROM read_audit")
    return {"ready": True}


def load_state(connection):
    row = connection.execute(
        "SELECT data FROM app_state WHERE id = 1"
    ).fetchone()
    if row is None:
        raise RuntimeError("Run setup before accessing application state")
    return json.loads(row[0])


def can_read(state, actor, asset):
    return (
        actor not in state["disabled"]
        and asset in state["owners"]
        and state["owners"][asset] == actor
        and asset in state["contents"]
    )


def read(connection, request):
    state = load_state(connection)
    actor = request["actor"]
    asset = request["asset"]

    response = {"decision": "deny"}
    if can_read(state, actor, asset):
        response = {"decision": "allow", "body": state["contents"][asset]}

    connection.execute(
        """
        INSERT INTO read_audit (request_id, decision) VALUES (?, ?)
        ON CONFLICT(request_id) DO UPDATE SET decision = excluded.decision
        """,
        (request["request_id"], response["decision"]),
    )
    return response


def protected_read(connection, request):
    state = load_state(connection)
    actor = request["actor"]
    asset = request["asset"]

    if not can_read(state, actor, asset):
        return {"decision": "deny"}

    try:
        public_key = base64.b64decode(request["public_key"], validate=True)
    except (binascii.Error, TypeError, ValueError):
        return {"decision": "deny"}

    if len(public_key) != ml_kem_768.PUBLIC_KEY_SIZE:
        return {"decision": "deny"}

    ciphertext, shared_secret = ml_kem_768.encrypt(public_key)
    proof_input = (request["challenge"] + state["contents"][asset]).encode("utf-8")
    proof = hmac.digest(shared_secret, proof_input, "sha256").hex()

    return {
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "proof": proof,
    }

def revoke(connection, request):
    state = load_state(connection)
    actor = request["actor"]
    if actor not in state["disabled"]:
        state["disabled"].append(actor)
        connection.execute(
            "UPDATE app_state SET data = ? WHERE id = 1",
            (json.dumps(state),),
        )
    return {}


def audit(connection, request):
    request_id = request["request_id"]
    row = connection.execute(
        "SELECT decision FROM read_audit WHERE request_id = ?",
        (request_id,),
    ).fetchone()
    if row is None:
        return {}
    return {"request_id": request_id, "decision": row[0]}


def dispatch(request):
    handlers = {
        "setup": setup,
        "read": read,
        "revoke": revoke,
        "audit": audit,
        "protected_read": protected_read,
    }
    handler = handlers[request["op"]]
    with closing(sqlite3.connect(state_path())) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            response = handler(connection, request)
        return response