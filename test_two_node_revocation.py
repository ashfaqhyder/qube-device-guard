from concurrent.futures import ThreadPoolExecutor
from tempfile import TemporaryDirectory
from time import perf_counter

from test_protected_read import call_adapter


def read_on_node(state_dir, node, phase, actor, asset):
    # Each call starts a fresh adapter process. The node label identifies
    # the probe in the audit records and in the test output.
    request_id = f"{phase}-{node}-{actor}"
    return call_adapter(state_dir, {
        "op": "read",
        "actor": actor,
        "asset": asset,
        "request_id": request_id,
    })


def probe_revocation(state_dir, node):
    reply = read_on_node(state_dir, node, "after", "maya", "brief")
    return node, reply, perf_counter()


def main():
    with TemporaryDirectory() as state_dir:
        assert call_adapter(state_dir, {
            "op": "setup",
            "owners": {"brief": "maya", "peer-file": "arun"},
            "contents": {"brief": "demo note", "peer-file": "peer note"},
            "disabled": [],
            "key_material": "synthetic-only",
        }) == {"ready": True}

        for node in ("A", "B"):
            assert read_on_node(state_dir, node, "before", "maya", "brief") == {
                "decision": "allow",
                "body": "demo note",
            }
        print("PASS: both processes allowed Maya before revocation")

        with ThreadPoolExecutor(max_workers=2) as pool:
            started = perf_counter()
            call_adapter(state_dir, {"op": "revoke", "actor": "maya"})
            acknowledged = perf_counter()

            probes = [
                pool.submit(probe_revocation, state_dir, node)
                for node in ("A", "B")
            ]
            results = [probe.result() for probe in probes]

        for node, reply, finished in results:
            assert reply == {"decision": "deny"}, (node, reply)
            assert call_adapter(state_dir, {
                "op": "audit",
                "request_id": f"after-{node}-maya",
            }) == {"request_id": f"after-{node}-maya", "decision": "deny"}
            assert read_on_node(state_dir, node, "after", "arun", "peer-file") == {
                "decision": "allow",
                "body": "peer note",
            }
            print(f"PASS: {node} denied Maya at {(finished - started) * 1000:.1f} ms")

        last_denial = max(finished for _, _, finished in results)
        print("PASS: audit matched both denials and Arun kept access")
        print(f"Revocation acknowledgement: {(acknowledged - started) * 1000:.1f} ms")
        print(f"Last denial observed: {(last_denial - started) * 1000:.1f} ms")


if __name__ == "__main__":
    main()