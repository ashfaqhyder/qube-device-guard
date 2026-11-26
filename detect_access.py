"""Explain Track 4 practice access events and score optional public labels."""

import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from statistics import median


POSITIVE_LABELS = {
    "unexpected_role_change",
    "review_after_role_change",
    "lateral_movement_candidate",
}
EXPECTED_SERVICE_EDGES = {("reports", "catalog")}
MAX_OFFSET_MS = 5000
REVIEW_WINDOW = timedelta(minutes=5)


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as source:
        return list(csv.DictReader(source))


def group(event):
    return event["actor"], event["session_id"], event["correlation_id"]


def approved_grant(event, approvals, observed, event_time):
    approval_id = event["approval_id"]
    approval = approvals.get(approval_id)
    if approval is None or approval.get("operation") != "grant_role":
        return False
    return (
        observed.get(approval_id) == approval["approved_by"]
        and approval["subject"] == event["actor"]
        and approval["role"] == event["role_after"]
        and approval["scope"]
        and parse_time(approval["valid_from_utc"]) <= event_time
        < parse_time(approval["valid_until_utc"])
    )


def detect(events, approvals):
    alerts = {}
    approval_events = {}
    unexpected_grants = {}
    service_paths = defaultdict(list)
    latest_event_time = {}
    corrected_times = {}

    def emit(event, rule, received, evidence, reason):
        event_id = event["event_id"]
        delay = (received - corrected_times[event_id]).total_seconds() * 1000
        if event_id not in alerts:
            alerts[event_id] = delay if delay >= 0 else None
            path = "; ".join(
                f'{item["event_id"]} {item["source_service"]}->{item["target_service"]}'
                f' ({item["outcome"]})' for item in evidence
            )
            print(f'ALERT {event_id} {rule} actor={event["actor"]}: {reason}; {path}')

    for event in events:  # The toolkit supplies these rows in receipt order.
        event_id = event["event_id"]
        source_time = parse_time(event["event_time_utc"])
        received = parse_time(event["received_time_utc"])
        offset_ms = int(event["source_clock_offset_ms"])
        corrected = source_time - timedelta(milliseconds=offset_ms)
        corrected_times[event_id] = corrected
        key = group(event)
        earlier_than_seen = key in latest_event_time and corrected < latest_event_time[key]
        uncertain = abs(offset_ms) > MAX_OFFSET_MS or received < corrected
        if earlier_than_seen or offset_ms or uncertain:
            delay = (received - corrected).total_seconds() * 1000
            print(
                f"TIMING {event_id} source={source_time.isoformat()} "
                f"received={received.isoformat()} corrected={corrected.isoformat()} "
                f"offset_ms={offset_ms} delay_ms={delay:.0f} "
                f"out_of_order={earlier_than_seen} order_uncertain={uncertain}"
            )
        if uncertain:
            continue
        latest_event_time[key] = max(corrected, latest_event_time.get(key, corrected))

        action = event["action"]
        if action == "approve_role_change" and event["outcome"] == "success":
            approval_events[event["approval_id"]] = event["actor"]

        if (
            action == "role_change"
            and event["outcome"] == "success"
            and event["role_before"] != event["role_after"]
        ):
            if approved_grant(event, approvals, approval_events, corrected):
                unexpected_grants.pop(key, None)
                print(f'APPROVED {event_id} {event["approval_id"]}')
            else:
                unexpected_grants[key] = event
                emit(event, "unexpected_role_change", received, [event],
                     "no matching approved grant")

        grant = unexpected_grants.get(key)
        if action == "read" and event["outcome"] == "allow" and grant:
            elapsed = corrected - corrected_times[grant["event_id"]]
            if timedelta(0) <= elapsed <= REVIEW_WINDOW:
                emit(event, "review_after_role_change", received, [grant, event],
                     "allowed read followed an unexpected role change")

        edge = event["source_service"], event["target_service"]
        if (
            event["actor"].startswith("svc-")
            and action in {"read", "list_roles"}
            and edge not in EXPECTED_SERVICE_EDGES
        ):
            path = service_paths[key]
            if path:
                previous = path[-1]
                elapsed = corrected - corrected_times[previous["event_id"]]
                if elapsed < timedelta(0):
                    print(f"TIMING {event_id} path order uncertain; late edge held out")
                    continue
                if elapsed > REVIEW_WINDOW or previous["target_service"] != edge[0]:
                    path.clear()
            path.append(event)
            if len(path) >= 2:
                for member in path:
                    emit(member, "lateral_movement_candidate", received, path,
                         "connected unexpected service edges; see recorded outcomes")

    return alerts


def score(events, alerts, label_rows):
    labels = {row["event_id"]: row["label"] for row in label_rows}
    if set(labels) != {event["event_id"] for event in events}:
        raise ValueError("Labels must cover exactly the event IDs being evaluated")
    expected = {event_id for event_id, label in labels.items() if label in POSITIVE_LABELS}
    predicted = set(alerts)
    tp = len(expected & predicted)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    benign = len(labels) - len(expected)
    f1 = (2 * tp / (2 * tp + fp + fn)) if (2 * tp + fp + fn) else 0.0
    rate = f"{1000 * fp / benign:.1f}" if benign else "unavailable"
    delays = [alerts[i] for i in expected & predicted if alerts[i] is not None]
    timing = f"{median(delays):.1f} ms" if delays else "unavailable"
    print(f"PRACTICE ONLY: TP={tp} FP={fp} FN={fn} benign={benign} F1={f1:.3f}")
    print(f"False alerts per 1000 benign events: {rate}")
    print(f"Median event-to-alert time among timed true positives: {timing}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("practice_dir", type=Path)
    parser.add_argument("--evaluate", action="store_true")
    args = parser.parse_args()

    events = read_csv(args.practice_dir / "events.csv")
    approval_file = args.practice_dir / "approvals.json"
    changes = json.loads(approval_file.read_text(encoding="utf-8-sig"))["changes"]
    approvals = {change["approval_id"]: change for change in changes}
    alerts = detect(events, approvals)

    if args.evaluate:
        score(events, alerts, read_csv(args.practice_dir / "labels.csv"))


if __name__ == "__main__":
    main()
