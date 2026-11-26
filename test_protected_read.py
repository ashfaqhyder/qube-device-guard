import base64
import hmac
import json
import os
import subprocess
import sys
from tempfile import TemporaryDirectory

from pqcrypto.kem import ml_kem_768


def call_adapter(state_dir, request):
    result = subprocess.run(
        [sys.executable, "track4_service.py"],
        input=json.dumps(request),
        capture_output=True,
        encoding="utf-8",
        env={**os.environ, "TRACK4_STATE_DIR": state_dir},
        check=True,
    )
    return json.loads(result.stdout)


if __name__ == "__main__":
    public_key, secret_key = ml_kem_768.generate_keypair()

    with TemporaryDirectory() as state_dir:
        setup = call_adapter(state_dir, {
            "op": "setup",
            "owners": {"brief": "maya"},
            "contents": {"brief": "demo note"},
            "disabled": [],
            "key_material": "synthetic-only",
        })
        assert setup == {"ready": True}

        request = {
            "op": "protected_read",
            "actor": "maya",
            "asset": "brief",
            "challenge": "test-challenge-01",
            "public_key": base64.b64encode(public_key).decode("ascii"),
        }

        response = call_adapter(state_dir, request)
        assert set(response) == {"ciphertext", "proof"}
        ciphertext = base64.b64decode(response["ciphertext"], validate=True)
        shared_secret = ml_kem_768.decrypt(secret_key, ciphertext)
        expected = hmac.digest(
            shared_secret, b"test-challenge-01demo note", "sha256"
        ).hex()
        assert hmac.compare_digest(response["proof"], expected)
        print("PASS: authorized protected read produces a valid proof")

        call_adapter(state_dir, {"op": "revoke", "actor": "maya"})
        denied = call_adapter(
            state_dir, {**request, "challenge": "test-challenge-02"}
        )
        assert denied == {"decision": "deny"}
        print("PASS: revoked actor receives no ciphertext, proof, or file body")