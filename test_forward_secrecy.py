"""Check key separation after a completed synthetic report transfer."""

from dataclasses import replace

from pqcrypto.sign import ml_dsa_65

from encrypted_report_demo import DeliveryRejected, Receiver, seal_report


def main():
    monitor_public, monitor_signing_key = ml_dsa_65.generate_keypair()
    doctor = Receiver("doctor-a", monitor_public)

    body = b"Synthetic report from the completed session"
    archived_report = seal_report(
        "doctor-a", doctor.public_key, monitor_signing_key, body
    )
    assert doctor.deliver(archived_report) == body
    assert doctor._session_key is None
    print("PASS: completed receiver session released its reference to the KEM key")

    # Simulate disclosure of only the long-term signing key after delivery.
    disclosed_signing_key = monitor_signing_key
    resigned_report = replace(
        archived_report,
        signature=ml_dsa_65.sign(
            disclosed_signing_key, archived_report.signed_bytes()
        ),
    )
    assert ml_dsa_65.verify(
        monitor_public, resigned_report.signed_bytes(), resigned_report.signature
    )
    print("PASS: the disclosed identity key could still sign the archived package")

    fresh_session = Receiver("doctor-a", monitor_public)
    assert fresh_session.public_key != doctor.public_key

    try:
        fresh_session.deliver(resigned_report)
    except DeliveryRejected as exc:
        assert str(exc) == "report authentication failed", str(exc)
    else:
        raise AssertionError("A fresh session decrypted the archived report")

    print("PASS: the valid signature did not let a fresh session decrypt the report")

    fresh_body = b"Synthetic report for the fresh session"
    fresh_report = seal_report(
        "doctor-a", fresh_session.public_key, monitor_signing_key, fresh_body
    )
    assert fresh_session.deliver(fresh_report) == fresh_body
    print("PASS: the fresh session still delivered its own report")


if __name__ == "__main__":
    main()