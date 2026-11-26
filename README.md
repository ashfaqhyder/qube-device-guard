# Qube Device Guard

A personal Python security prototype for post-quantum device authentication,
encrypted report delivery, and auditable key management.

Qube Device Guard models a hospital receiving a synthetic heart-monitor report.
It demonstrates how a service can replace a device key, block a lost device,
keep a peer's access working, and recover after an interrupted rotation.

The project began during Yugaantar DevForge as a prototype for Track 4,
“Trust, but verify.” It is maintained as a personal project after the team
switched tracks.

## What it demonstrates

| Capability | What the local tests verify |
| --- | --- |
| Device authentication | ML-DSA-65 signed requests are checked against the active public key and version. |
| Key rotation | Both local workers reject the old key after commit. A transfer admitted before rotation can finish. |
| Device loss and re-enrolment | The lost key is blocked, a replacement key restores the owner's access, and a peer retains access. |
| Recovery | An interrupted rotation preserves the correct committed key. Backup restoration rejects stale and damaged snapshots. |
| Encrypted delivery | A mock report uses ML-KEM-768 and AES-GCM, with sender signatures, recipient binding, and duplicate rejection. The relay tests loss and reordering. |
| Audit and monitoring | A verifiable key-event log records operator actions. Rules explain unexpected privilege changes and unusual service paths. |

## Run the local demos

The examples below use Windows Command Prompt and Python 3.12. From the
repository root, install the dependencies:

```cmd
py -3.12 -m pip install pqcrypto==0.4.0 cryptography
```

Run an encrypted-report demo, a device replacement, or a recovery test:

```cmd
py -3.12 encrypted_report_demo.py
py -3.12 device_reenrollment.py
py -3.12 test_rotation_recovery.py
```

For the full acceptance suite, extract the
[Track 4 Toolkit v1.0.0](https://github.com/BUTTERFINGERS7498/trust-but-verify-toolkit/archive/refs/tags/v1.0.0.zip)
beside this repository in a folder called `track4-toolkit`, then run:

```cmd
run_acceptance.cmd
```

The runner executes the local Python checks, scores the detector against the
toolkit's public practice data, and runs the organizer's local lost-device
validator. `track4_service.py` retains the original JSON adapter so those
checks remain reproducible.

## Verification and scope

The Windows acceptance suite passed on commit
[`94349c2`](https://github.com/ashfaqhyder/qube-device-guard/commit/94349c20b6f7540f481fc5828e238cdef1ba3e83).
On the toolkit's 22 public practice events, the detector reported F1 1.000
with five true positives and zero false positives or false negatives. The
200 ms median event-to-alert time comes from synthetic timestamps.

The prototype uses test identities and synthetic data. Two local workers share
SQLite, and the relay simulates transport in one process. Backup restoration
assumes access-control state survives, and the audit checkpoint is held in
test memory. Recipient sessions support one transfer each. Secure memory
erasure and deployment across separate state stores remain unverified.

## Research and toolkit credits

The device-authentication design was informed by Riva-Cambrin et al.,
“Extensible Post Quantum Cryptography-Based Authentication,”
IEEE Transactions on Information Forensics and Security, 2026.
[Read the paper](https://doi.org/10.1109/TIFS.2026.3705933).

The adapter interface, validator, and public practice data come from the
[Yugaantar DevForge Track 4 Toolkit](https://github.com/BUTTERFINGERS7498/trust-but-verify-toolkit).