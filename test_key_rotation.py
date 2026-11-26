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


def main():
    old_public_key, _ = ml_dsa_65.generate_keypair()
    new_public_key, _ = ml_dsa_65.generate_keypair()

    with TemporaryDirectory() as state_dir:
        database = Path(state_dir) / "state.sqlite3"

        with closing(sqlite3.connect(database)) as connection:
            with connection:
                initialize_registry(connection)
                enrol_device(connection, "maya", old_public_key)
            assert active_key(connection, "maya") == (1, old_public_key)
            print("PASS: Maya starts with key version 1")

            with connection:
                assert rotate_device_key(connection, "maya", 1, new_public_key)

        with closing(sqlite3.connect(database)) as connection:
            assert active_key(connection, "maya") == (2, new_public_key)
            print("PASS: a fresh connection sees key version 2")

            with connection:
                assert not rotate_device_key(connection, "maya", 1, old_public_key)
            assert active_key(connection, "maya") == (2, new_public_key)
            print("PASS: a stale rotation cannot restore the old key")


if __name__ == "__main__":
    main()