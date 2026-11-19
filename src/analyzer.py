import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict, deque
from datetime import timedelta
import json
import csv

# Locate the project directory
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "auth.log"

# Match SSH authentication events
LOG_PATTERN = re.compile(
    r"(?P<timestamp>\S+)\s+"
    r"sshd\[\d+\]:\s+"
    r"(?P<status>Accepted|Failed)\s+"
    r"(?P<method>password|publickey)\s+"
    r"for\s+(?:invalid user\s+)?"
    r"(?P<username>\S+)\s+"
    r"from\s+(?P<source_ip>\S+)\s+"
    r"port\s+\d+\s+ssh2"
)


def parse_logs(file_path):
    events = []

    with open(file_path, "r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            match = LOG_PATTERN.search(line)

            if not match:
                print(f"[WARNING] Unrecognized log line: {line_number}")
                continue

            event = match.groupdict()

            event["timestamp"] = datetime.fromisoformat(
                event["timestamp"]
            )

            event["status"] = (
                "SUCCESS"
                if event["status"] == "Accepted"
                else "FAILED"
            )

            events.append(event)

    return events


def detect_brute_force(events, threshold=5, window_minutes=2):
    alerts = []
    failed_by_ip = defaultdict(list)

    # Group failed authentication events by source IP
    for event in events:
        if event["status"] == "FAILED":
            failed_by_ip[event["source_ip"]].append(event)

    for source_ip, failures in failed_by_ip.items():
        failures.sort(key=lambda event: event["timestamp"])

        window = deque()

        for event in failures:
            current_time = event["timestamp"]

            window.append(event)

            # Remove failures outside the detection window
            while (
                window
                and current_time - window[0]["timestamp"]
                > timedelta(minutes=window_minutes)
            ):
                window.popleft()

            if len(window) == threshold:
                alerts.append({
                    "alert_type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "source_ip": source_ip,
                    "failed_attempts": len(window),
                    "targeted_users": sorted({
                        item["username"] for item in window
                    }),
                    "first_seen": window[0]["timestamp"],
                    "last_seen": current_time
                })

    return alerts


def detect_password_spraying(events, threshold=4, window_minutes=2):
    alerts = []
    failed_by_ip = defaultdict(list)

    # Group failed authentication attempts by source IP
    for event in events:
        if event["status"] == "FAILED":
            failed_by_ip[event["source_ip"]].append(event)

    for source_ip, failures in failed_by_ip.items():
        failures.sort(key=lambda event: event["timestamp"])

        window = deque()
        alerted = False

        for event in failures:
            current_time = event["timestamp"]
            window.append(event)

            # Keep only events within the time window
            while (
                window
                and current_time - window[0]["timestamp"]
                > timedelta(minutes=window_minutes)
            ):
                window.popleft()

            unique_users = sorted({
                item["username"] for item in window
            })

            if len(unique_users) >= threshold and not alerted:
                alerts.append({
                    "alert_type": "PASSWORD_SPRAYING",
                    "severity": "HIGH",
                    "source_ip": source_ip,
                    "failed_attempts": len(window),
                    "targeted_users": unique_users,
                    "first_seen": window[0]["timestamp"],
                    "last_seen": current_time
                })

                alerted = True

    return alerts


def detect_suspicious_success(events, threshold=3, window_minutes=5):
    alerts = []

    # Group authentication events by source IP and username
    events_by_account = defaultdict(list)

    for event in events:
        key = (event["source_ip"], event["username"])
        events_by_account[key].append(event)

    for (source_ip, username), account_events in events_by_account.items():
        account_events.sort(key=lambda event: event["timestamp"])

        failed_window = deque()

        for event in account_events:
            current_time = event["timestamp"]

            # Remove failed attempts older than the time window
            while (
                failed_window
                and current_time - failed_window[0]["timestamp"]
                > timedelta(minutes=window_minutes)
            ):
                failed_window.popleft()

            if event["status"] == "FAILED":
                failed_window.append(event)

            elif event["status"] == "SUCCESS":
                if len(failed_window) >= threshold:
                    alerts.append({
                        "alert_type": "SUCCESS_AFTER_FAILURES",
                        "severity": "HIGH",
                        "source_ip": source_ip,
                        "username": username,
                        "failed_attempts": len(failed_window),
                        "first_failure": failed_window[0]["timestamp"],
                        "successful_login": current_time
                    })

                # Reset after a successful authentication
                failed_window.clear()

    return alerts


def export_alerts(alerts):
    reports_dir = BASE_DIR / "reports"
    reports_dir.mkdir(exist_ok=True)

    json_file = reports_dir / "security_alerts.json"
    csv_file = reports_dir / "security_alerts.csv"

    # Convert datetime objects to strings for exporting
    formatted_alerts = []

    for alert in alerts:
        formatted_alert = {}

        for key, value in alert.items():
            if isinstance(value, datetime):
                formatted_alert[key] = value.isoformat()
            elif isinstance(value, list):
                formatted_alert[key] = ", ".join(value)
            else:
                formatted_alert[key] = value

        formatted_alerts.append(formatted_alert)

    # Export alerts to JSON
    with open(json_file, "w", encoding="utf-8") as file:
        json.dump(formatted_alerts, file, indent=4)

    # Export alerts to CSV
    fieldnames = [
        "alert_type",
        "severity",
        "source_ip",
        "username",
        "failed_attempts",
        "targeted_users",
        "first_seen",
        "last_seen",
        "first_failure",
        "successful_login"
    ]

    with open(csv_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore"
        )

        writer.writeheader()
        writer.writerows(formatted_alerts)

    print("\n=== Security Reports Generated ===")
    print(f"JSON report: {json_file}")
    print(f"CSV report: {csv_file}")
    print(f"Total alerts exported: {len(alerts)}")


def main():
    print("=== Python Security Log Analyzer ===")

    events = parse_logs(LOG_FILE)

    print(f"\nTotal authentication events: {len(events)}")

    successful = sum(
        1 for event in events if event["status"] == "SUCCESS"
    )

    failed = sum(
        1 for event in events if event["status"] == "FAILED"
    )

    print(f"Successful logins: {successful}")
    print(f"Failed logins: {failed}")

    print("\nParsed authentication events:")

    for event in events:
        print(
            f"{event['timestamp']} | "
            f"{event['source_ip']} | "
            f"{event['username']} | "
            f"{event['status']}"
        )

    # Detection runs after all events have been displayed
    print("\n=== Brute-Force Detection ===")

    alerts = detect_brute_force(events)

    if not alerts:
        print("No brute-force activity detected.")
    else:
        for alert in alerts:
            print(f"\n[HIGH] {alert['alert_type']}")
            print(f"Source IP: {alert['source_ip']}")
            print(f"Failed attempts: {alert['failed_attempts']}")
            print(f"Targeted users: {', '.join(alert['targeted_users'])}")
            print(f"First seen: {alert['first_seen']}")
            print(f"Last seen: {alert['last_seen']}")

        
    # Password-spraying detection
    print("\n=== Password-Spraying Detection ===")

    spray_alerts = detect_password_spraying(events)

    if not spray_alerts:
        print("No password-spraying activity detected.")
    else:
        for alert in spray_alerts:
            print(f"\n[HIGH] {alert['alert_type']}")
            print(f"Source IP: {alert['source_ip']}")
            print(f"Failed attempts: {alert['failed_attempts']}")
            print(f"Targeted users: {', '.join(alert['targeted_users'])}")
            print(f"First seen: {alert['first_seen']}")
            print(f"Last seen: {alert['last_seen']}")


    # Successful login after repeated failures
    print("\n=== Suspicious Successful Login Detection ===")

    suspicious_logins = detect_suspicious_success(events)

    if not suspicious_logins:
        print("No suspicious successful logins detected.")
    else:
        for alert in suspicious_logins:
            print(f"\n[HIGH] {alert['alert_type']}")
            print(f"Source IP: {alert['source_ip']}")
            print(f"Username: {alert['username']}")
            print(f"Previous failed attempts: {alert['failed_attempts']}")
            print(f"First failure: {alert['first_failure']}")
            print(f"Successful login: {alert['successful_login']}")

        # Combine all detected security alerts
    all_alerts = alerts + spray_alerts + suspicious_logins

    # Generate JSON and CSV reports
    export_alerts(all_alerts)



if __name__ == "__main__":
    main()

