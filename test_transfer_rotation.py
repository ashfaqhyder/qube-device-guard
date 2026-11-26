"""Prove mock transfer continuity across a committed signing-key rotation."""

import sqlite3
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from pqcrypto.sign import ml_dsa_65

from device_keys import (
    active_key,
    enrol_device,
    initialize_registry,
    rotate_device_key,
)
from encrypted_report_demo import DeliveryRejected, Receiver, seal_report
from test_report_delivery import deliver_chunks, relay_chunks


def admit_transfer(database, actor, report):
    """Check the package against the currently registered signing key."""
    with closing(sqlite3.connect(database)) as connection:
        registered = active_key(connection, actor)

    if registered is None:
        raise DeliveryRejected("device key is not registered")

    _, public_key = registered
    if not ml_dsa_65.verify(public_key, report.signed_bytes(), report.signature):
        raise DeliveryRejected("package was not signed by the active key")

    return report


def finish_admitted_transfer(receiver, admitted, arrivals):
    """Accept only chunks that reconstruct the already admitted package."""
    original_chunks = relay_chunks(admitted.encrypted_body)
    for index, chunk in arrivals:
        if not 0 <= index < len(original_chunks):
            raise DeliveryRejected("invalid chunk index")
        if chunk != original_chunks[index][1]:
            raise DeliveryRejected("chunk differs from the admitted package")

    envelope = replace(admitted, encrypted_body=b"")
    return deliver_chunks(receiver, envelope, len(original_chunks), arrivals)


def main():
    old_public, old_secret = ml_dsa_65.generate_keypair()
    new_public, new_secret = ml_dsa_65.generate_keypair()
    actor = "mock-monitor"
    body = b"Synthetic heart-monitor report started before key rotation."

    with TemporaryDirectory() as directory:
        database = Path(directory) / "state.sqlite3"
        with closing(sqlite3.connect(database)) as connection:
            with connection:
                initialize_registry(connection)
                enrol_device(connection, actor, old_public)

        doctor = Receiver("doctor-a", old_public)
        report = seal_report("doctor-a", doctor.public_key, old_secret, body)
        admitted = admit_transfer(database, actor, report)
        chunks = relay_chunks(admitted.encrypted_body)
        assert len(chunks) >= 2
        arrivals_before_rotation = chunks[:1]
        print("PASS: version 1 transfer was admitted and its first chunk arrived")

        with closing(sqlite3.connect(database)) as connection:
            with connection:
                rotated = rotate_device_key(connection, actor, 1, new_public)
                assert rotated

        arrivals_after_rotation = list(reversed(chunks[1:]))
        recovered = finish_admitted_transfer(
            doctor, admitted, arrivals_before_rotation + arrivals_after_rotation
        )
        assert recovered == body
        print("PASS: the admitted transfer finished after rotation committed")

        next_doctor = Receiver("doctor-a", new_public)
        stale_package = seal_report(
            "doctor-a", next_doctor.public_key, old_secret, b"New stale-key report"
        )
        try:
            admit_transfer(database, actor, stale_package)
        except DeliveryRejected as exc:
            assert str(exc) == "package was not signed by the active key"
        else:
            raise AssertionError("A new transfer signed by version 1 was admitted")
        print("PASS: a new transfer signed by version 1 was rejected")

        new_body = b"Synthetic report started after key rotation"
        new_package = seal_report(
            "doctor-a", next_doctor.public_key, new_secret, new_body
        )
        new_admission = admit_transfer(database, actor, new_package)
        assert finish_admitted_transfer(
            next_doctor, new_admission, relay_chunks(new_admission.encrypted_body)
        ) == new_body
        print("PASS: a new transfer signed by version 2 was admitted and delivered")


if __name__ == "__main__":
    main()