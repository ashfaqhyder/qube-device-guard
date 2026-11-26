"""Exercise the access detector with additional synthetic events."""

from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO

from detect_access import detect


BASE_TIME = datetime(2026, 1, 16, 9, 0, tzinfo=timezone.utc)


def make_event(event_id, seconds, source, target, *, offset_ms=0):
    corrected = BASE_TIME + timedelta(seconds=seconds)
    return {
        "event_id": event_id,
        "event_time_utc": (
            corrected + timedelta(milliseconds=offset_ms)
        ).isoformat(),
        "received_time_utc": (
            corrected + timedelta(milliseconds=250)
        ).isoformat(),
        "source_clock_offset_ms": str(offset_ms),
        "actor": "svc-synthetic-worker",
        "source_service": source,
        "target_service": target,
        "action": "read",
        "role_before": "service-reader",
        "role_after": "service-reader",
        "outcome": "allow",
        "approval_id": "",
        "session_id": "synthetic-session",
        "correlation_id": "synthetic-flow",
    }


def run_detector(events):
    output = StringIO()
    with redirect_stdout(output):
        alerts = detect(events, {})
    return alerts, output.getvalue()


def main():
    first = make_event("test-01", 1, "reports", "inventory")
    uncertain = make_event("test-02", 2, "inventory", "exports", offset_ms=6000)
    last = make_event("test-03", 3, "inventory", "archive")
    routine = make_event("test-04", 0, "reports", "catalog")

    alerts, output = run_detector([routine, first, uncertain])
    assert alerts == {}, alerts
    assert any(
        line.startswith("TIMING test-02 ") and "order_uncertain=True" in line
        for line in output.splitlines()
    ), output
    print("PASS: out-of-range clock offset was flagged and excluded from correlation")

    alerts, output = run_detector([routine, first, uncertain, last])
    assert set(alerts) == {"test-01", "test-03"}, alerts
    alert_lines = [
        line for line in output.splitlines() if line.startswith("ALERT ")
    ]
    assert len(alert_lines) == 2, output
    for line in alert_lines:
        assert "actor=svc-synthetic-worker" in line, line
        assert "test-01 reports->inventory (allow)" in line, line
        assert "test-03 inventory->archive (allow)" in line, line
        assert "test-02" not in line, line

    print("PASS: allowed unusual path was flagged with both supporting events")
    print("PASS: routine reports-to-catalog access stayed unflagged")


if __name__ == "__main__":
    main()