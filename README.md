# Qube Device Guard

Track 4 · Trust, but verify · Yugaantar DevForge

Qube Device Guard demonstrates how a mock hospital can protect a synthetic
heart-monitor report while device keys change, devices are revoked, and service
processes restart. The project combines post-quantum device authentication,
encrypted delivery, verifiable operator logs, and explainable access alerts.

## Organizer entry point

`track4_service.py` implements the Track 4 adapter. It reads one JSON object
from stdin and writes one JSON object to stdout. Supported operations are
`setup`, `read`, `revoke`, `audit`, and `protected_read`.

The adapter uses Python 3.12 and `pqcrypto==0.4.0` for the ML-KEM-768
protected-read exchange. SQLite state is kept under `TRACK4_STATE_DIR` when
provided, with a fallback to the system temporary directory.

## Local setup and acceptance

On Windows, place the extracted Track 4 Toolkit v1.0.0 in a sibling folder
named `track4-toolkit`. From the project root, run:

```cmd
py -3.12 -m pip install pqcrypto==0.4.0 cryptography
run_acceptance.cmd
```

The `cryptography` package is used by the separate AES-GCM messaging demo.
The acceptance runner executes the local checks, evaluates the detector against
the toolkit's public practice data, and runs the organizer's lost-device
validator. A successful run ends with:

```text
PASS: all local acceptance commands completed successfully
```

## Design

- **Device identity and key lifecycle.** ML-DSA-65 signed requests use a
  versioned public-key registry. Two local workers share SQLite. The rotation
  commit is the cutoff, with zero grace for new requests signed by the old key.
  A replacement key lets the owner regain access after device loss.
- **Encrypted delivery.** The mock sender uses ML-KEM-768 and AES-GCM for a
  one-transfer recipient session. The receiver checks the sender signature and
  recipient before delivery. Local relay tests cover reordering, loss,
  retransmission, replay, and completion of a transfer admitted before rotation.
- **Recovery and audit.** Local tests interrupt rotation before and after
  commit, check signed backups before restoring a missing key, and verify
  rotation and revocation events against an HMAC log checkpoint.
- **Access monitoring.** `detect_access.py` uses deterministic rules and
  approval context to explain unexpected role changes and unusual service paths.
  On the 22 public practice events it reported F1 1.000, with five true
  positives, zero false positives, and zero false negatives. The 200 ms median
  event-to-alert time comes from synthetic event timestamps.

## Evidence and limits

The project uses synthetic data and test identities. The two-worker tests use
shared SQLite. The relay simulates transport in one process, and the backup
test assumes access-control state survives. The audit checkpoint is kept in
test memory. The key-separation test checks what a later signing-key disclosure
exposes in the mock session. Secure memory erasure remains unverified. Sessions
are single-transfer, with no session resumption.

## Research reference

Riva-Cambrin et al., “Extensible Post Quantum Cryptography-Based
Authentication,” IEEE Transactions on Information Forensics and Security,
2026. DOI 10.1109/TIFS.2026.3705933.