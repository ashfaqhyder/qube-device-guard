import sqlite3
from concurrent.futures import ProcessPoolExecutor
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

from pqcrypto.sign import ml_dsa_65

from device_keys import enrol_device, initialize_registry, rotate_device_key
from signed_reads import signed_payload, signed_read
from test_protected_read import call_adapter


def probe(worker, database, actor, asset, request_id, version, secret_key):
    message = signed_payload(actor, asset, request_id, version)
    signature = ml_dsa_65.sign(secret_key, message)
    return worker.submit(
        signed_read, database, actor, asset, request_id, version, signature
    ).result(timeout=15)


def main():
    old_public, old_secret = ml_dsa_65.generate_keypair()
    new_public, new_secret = ml_dsa_65.generate_keypair()
    peer_public, peer_secret = ml_dsa_65.generate_keypair()

    with TemporaryDirectory() as state_dir:
        database = Path(state_dir) / "state.sqlite3"
        assert call_adapter(state_dir, {
            "op": "setup",
            "owners": {"brief": "maya", "peer-file": "arun"},
            "contents": {"brief": "demo note", "peer-file": "peer note"},
            "disabled": [],
            "key_material": "synthetic-only",
        }) == {"ready": True}

        with closing(sqlite3.connect(database)) as connection:
            with connection:
                initialize_registry(connection)
                enrol_device(connection, "maya", old_public)
                enrol_device(connection, "arun", peer_public)

        allow_maya = {"decision": "allow", "body": "demo note"}
        allow_arun = {"decision": "allow", "body": "peer note"}
        deny = {"decision": "deny"}

        with ProcessPoolExecutor(max_workers=1) as worker_a, \
                ProcessPoolExecutor(max_workers=1) as worker_b:
            workers = {"A": worker_a, "B": worker_b}

            for node, worker in workers.items():
                assert probe(
                    worker, database, "maya", "brief",
                    f"{node}-before", 1, old_secret,
                ) == allow_maya
                print(f"PASS: {node} accepted Maya's version 1 before rotation")

            with closing(sqlite3.connect(database)) as connection:
                with connection:
                    rotated = rotate_device_key(connection, "maya", 1, new_public)
                assert rotated
            print("Rotation committed. Version 2 is active. No grace period.")

            for node, worker in workers.items():
                assert probe(
                    worker, database, "maya", "brief",
                    f"{node}-old", 1, old_secret,
                ) == deny
                assert probe(
                    worker, database, "maya", "brief",
                    f"{node}-wrong-signature", 2, old_secret,
                ) == deny
                assert probe(
                    worker, database, "maya", "brief",
                    f"{node}-new", 2, new_secret,
                ) == allow_maya
                assert probe(
                    worker, database, "maya", "brief",
                    f"{node}-new", 2, new_secret,
                ) == deny
                assert probe(
                    worker, database, "arun", "peer-file",
                    f"{node}-peer", 1, peer_secret,
                ) == allow_arun
                print(
                    f"PASS: {node} rejected the old key and duplicate read, "
                    "accepted the new key, and kept Arun's access"
                )


if __name__ == "__main__":
    main()