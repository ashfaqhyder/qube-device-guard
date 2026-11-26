"""Local Track 4 demo for one synthetic report and one recipient session."""

import json
from dataclasses import dataclass, replace
from secrets import token_bytes, token_hex

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65


class DeliveryRejected(ValueError):
    """The receiver refused to deliver the report."""


def encode_fields(*fields):
    """Frame fields reproducibly before signing or authenticating them."""
    return json.dumps(fields, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class Report:
    recipient: str
    transfer_id: str
    kem_ciphertext: bytes
    nonce: bytes
    encrypted_body: bytes
    signature: bytes

    def header(self):
        return encode_fields(
            "qube-report-v1", self.recipient, self.transfer_id
        )

    def signed_bytes(self):
        return encode_fields(
            "qube-signed-report-v1",
            self.recipient,
            self.transfer_id,
            self.kem_ciphertext.hex(),
            self.nonce.hex(),
            self.encrypted_body.hex(),
        )


def seal_report(recipient, recipient_public_key, monitor_signing_key, body):
    kem_ciphertext, shared_secret = ml_kem_768.encrypt(recipient_public_key)
    report = Report(
        recipient=recipient,
        transfer_id=token_hex(16),
        kem_ciphertext=kem_ciphertext,
        nonce=token_bytes(12),
        encrypted_body=b"",
        signature=b"",
    )
    report = replace(
        report,
        encrypted_body=AESGCM(shared_secret).encrypt(
            report.nonce, body, report.header()
        ),
    )
    return replace(
        report,
        signature=ml_dsa_65.sign(monitor_signing_key, report.signed_bytes()),
    )


class Receiver:
    def __init__(self, recipient, trusted_monitor_key):
        self.recipient = recipient
        self.trusted_monitor_key = trusted_monitor_key
        self.public_key, self._session_key = ml_kem_768.generate_keypair()

    def deliver(self, report):
        if report.recipient != self.recipient:
            raise DeliveryRejected("recipient mismatch")

        if self._session_key is None:
            raise DeliveryRejected("session already consumed")

        if not ml_dsa_65.verify(
            self.trusted_monitor_key, report.signed_bytes(), report.signature
        ):
            raise DeliveryRejected("signature verification failed")

        try:
            shared_secret = ml_kem_768.decrypt(
                self._session_key, report.kem_ciphertext
            )
            body = AESGCM(shared_secret).decrypt(
                report.nonce, report.encrypted_body, report.header()
            )
        except (InvalidTag, ValueError) as exc:
            raise DeliveryRejected("report authentication failed") from exc

        self._session_key = None
        return body


def expect_rejection(receiver, report, expected_reason):
    try:
        receiver.deliver(report)
    except DeliveryRejected as exc:
        assert str(exc) == expected_reason, str(exc)
        return

    raise AssertionError("Receiver delivered a report that should be rejected")


def main():
    monitor_public, monitor_secret = ml_dsa_65.generate_keypair()
    doctor = Receiver("doctor-a", monitor_public)
    other_doctor = Receiver("doctor-b", monitor_public)
    unrelated_session = Receiver("doctor-a", monitor_public)

    body = b"Synthetic heart-monitor report"
    report = seal_report("doctor-a", doctor.public_key, monitor_secret, body)

    expect_rejection(other_doctor, report, "recipient mismatch")
    expect_rejection(
        unrelated_session, report, "report authentication failed"
    )
    print("PASS: a different recipient and a different session were denied")

    expect_rejection(
        other_doctor,
        replace(report, recipient="doctor-b"),
        "signature verification failed",
    )
    print("PASS: changing the recipient invalidated the monitor signature")

    assert doctor.deliver(report) == body
    print("PASS: the intended recipient recovered the exact synthetic report")

    expect_rejection(doctor, report, "session already consumed")
    print("PASS: resending the report did not produce a second delivery")


if __name__ == "__main__":
    main()