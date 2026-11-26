"""Versioned public keys for the mock device registry."""


def initialize_registry(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS device_keys (
            actor TEXT PRIMARY KEY,
            version INTEGER NOT NULL,
            public_key BLOB NOT NULL
        )
    """)


def enrol_device(connection, actor, public_key):
    connection.execute(
        "INSERT INTO device_keys (actor, version, public_key) VALUES (?, 1, ?)",
        (actor, public_key),
    )


def active_key(connection, actor):
    return connection.execute(
        "SELECT version, public_key FROM device_keys WHERE actor = ?",
        (actor,),
    ).fetchone()


def rotate_device_key(connection, actor, expected_version, new_public_key):
    result = connection.execute(
        """
        UPDATE device_keys
        SET version = version + 1, public_key = ?
        WHERE actor = ? AND version = ? AND public_key <> ?
        """,
        (new_public_key, actor, expected_version, new_public_key),
    )
    return result.rowcount == 1