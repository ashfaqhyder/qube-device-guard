"""Test synthetic report delivery through an in-process mock relay."""

from dataclasses import replace

from pqcrypto.sign import ml_dsa_65

from encrypted_report_demo import DeliveryRejected, Receiver, seal_report


def relay_chunks(encrypted_body, chunk_size=16):
    return [
        (number, encrypted_body[start:start + chunk_size])
        for number, start in enumerate(
            range(0, len(encrypted_body), chunk_size)
        )
    ]


def deliver_chunks(receiver, envelope, chunk_count, arrivals):
    """Finish one delivery attempt using the chunks received by its deadline."""
    pieces = {}
    for number, payload in arrivals:
        if not 0 <= number < chunk_count:
            raise DeliveryRejected("invalid chunk index")
        if number in pieces and pieces[number] != payload:
            raise DeliveryRejected("conflicting duplicate chunk")
        pieces[number] = payload

    if len(pieces) != chunk_count:
        raise DeliveryRejected("incomplete transfer")

    encrypted_body = b"".join(pieces[number] for number in range(chunk_count))
    return receiver.deliver(replace(envelope, encrypted_body=encrypted_body))


def expect_failure(receiver, envelope, count, arrivals, expected_reason):
    try:
        deliver_chunks(receiver, envelope, count, arrivals)
    except DeliveryRejected as exc:
        assert str(exc) == expected_reason, str(exc)
        return

    raise AssertionError("A failed transfer returned a report")


def main():
    monitor_public, monitor_secret = ml_dsa_65.generate_keypair()
    doctor = Receiver("doctor-a", monitor_public)
    body = b"Synthetic heart-monitor report for the Track 4 relay test."
    report = seal_report("doctor-a", doctor.public_key, monitor_secret, body)

    chunks = relay_chunks(report.encrypted_body)
    count = len(chunks)
    assert count >= 3
    envelope = replace(report, encrypted_body=b"")

    missing = chunks[:1] + chunks[2:]
    expect_failure(doctor, envelope, count, missing, "incomplete transfer")
    print("PASS: an attempt with a missing chunk returned no report")

    damaged = chunks.copy()
    number, payload = damaged[1]
    damaged[1] = (number, bytes([payload[0] ^ 1]) + payload[1:])
    expect_failure(
        doctor, envelope, count, damaged, "signature verification failed"
    )
    print("PASS: damaged ciphertext was rejected without delivery")

    # Simulate a fresh attempt. The missing chunk is retransmitted last.
    recovered = list(reversed(missing)) + [chunks[1]]
    assert deliver_chunks(doctor, envelope, count, recovered) == body
    print("PASS: reordered chunks and a retransmission recovered the exact report")

    expect_failure(
        doctor, envelope, count, recovered, "session already consumed"
    )
    print("PASS: replaying the complete transfer produced no second delivery")


if __name__ == "__main__":
    main()