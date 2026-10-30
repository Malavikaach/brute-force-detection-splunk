
import csv
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

# Project file paths
BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "login_logs.csv"
REPORT_FILE = BASE_DIR / "alerts.txt"
HISTORY_FILE = BASE_DIR / "alert_history.csv"

# Detection settings
FAILURE_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5

# Alert history columns
HISTORY_COLUMNS = [
    "detected_at",
    "ip_address",
    "failed_attempts",
    "time_window_minutes",
    "risk_level",
    "alert_message",
    "window_start",
    "window_end",
]


def alert_already_recorded(ip, window_start, window_end):
    """Check whether this exact IP detection window is already recorded."""
    if not HISTORY_FILE.exists():
        return False

    with HISTORY_FILE.open(
        "r", newline="", encoding="utf-8-sig"
    ) as history:
        reader = csv.DictReader(history)

        # An older history file may not have window columns.
        if not reader.fieldnames or not set(
            HISTORY_COLUMNS
        ).issubset(reader.fieldnames):
            return False

        for row in reader:
            if (
                row.get("ip_address") == ip
                and row.get("window_start")
                == window_start.strftime("%Y-%m-%d %H:%M:%S")
                and row.get("window_end")
                == window_end.strftime("%Y-%m-%d %H:%M:%S")
            ):
                return True

    return False


def save_alert(ip, failed_count, window_start, window_end, message):
    """Append a new detection to alert history, avoiding duplicate windows."""
    if alert_already_recorded(ip, window_start, window_end):
        print(f"Duplicate history entry skipped for {ip}.")
        return

    history_exists = HISTORY_FILE.exists()
    write_header = (
        not history_exists or HISTORY_FILE.stat().st_size == 0
    )

    # If an older six-column file exists, stop rather than corrupt it.
    if history_exists and not write_header:
        with HISTORY_FILE.open(
            "r", newline="", encoding="utf-8-sig"
        ) as history:
            reader = csv.reader(history)
            existing_header = next(reader, [])

        if existing_header != HISTORY_COLUMNS:
            raise ValueError(
                "alert_history.csv uses an older format. "
                "Back it up, then rename it to "
                "alert_history_old.csv before running again."
            )

    with HISTORY_FILE.open(
        "a", newline="", encoding="utf-8"
    ) as history:
        writer = csv.writer(history)

        if write_header:
            writer.writerow(HISTORY_COLUMNS)

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            failed_count,
            TIME_WINDOW_MINUTES,
            "HIGH",
            message,
            window_start.strftime("%Y-%m-%d %H:%M:%S"),
            window_end.strftime("%Y-%m-%d %H:%M:%S"),
        ])

    print(f"New alert recorded for {ip}.")


def analyze_logs():
    failed_attempts = Counter()
    failed_timestamps = defaultdict(deque)
    successful_logins = 0
    total_events = 0
    alerts = []
    alerted_ips = set()

    # Check whether the input file exists
    if not LOG_FILE.exists():
        print(f"Error: Log file not found: {LOG_FILE}")
        return

    # Read and validate the CSV
    with LOG_FILE.open(
        "r", newline="", encoding="utf-8-sig"
    ) as file:
        reader = csv.DictReader(file)

        required = {
            "timestamp",
            "ip_address",
            "username",
            "status",
        }

        if not reader.fieldnames or not required.issubset(
            reader.fieldnames
        ):
            print(
                "Error: CSV must contain timestamp, "
                "ip_address, username, status."
            )
            return

        # Read all events and sort them chronologically
        rows = list(reader)

    parsed_events = []

    for row in rows:
        try:
            event_time = datetime.strptime(
                row["timestamp"].strip(),
                "%Y-%m-%d %H:%M:%S",
            )
        except (ValueError, AttributeError, KeyError):
            print(
                "Skipping invalid timestamp:",
                row.get("timestamp", ""),
            )
            continue

        parsed_events.append((event_time, row))

    parsed_events.sort(key=lambda item: item[0])

    for event_time, row in parsed_events:
        total_events += 1
        ip = row.get("ip_address", "").strip()
        status = row.get("status", "").strip().upper()

        if not ip:
            continue

        if status == "SUCCESS":
            successful_logins += 1

        elif status == "FAILED":
            failed_attempts[ip] += 1
            recent = failed_timestamps[ip]

            cutoff = event_time - timedelta(
                minutes=TIME_WINDOW_MINUTES
            )

            # Remove attempts strictly older than five minutes
            while recent and recent[0] < cutoff:
                recent.popleft()

            recent.append(event_time)

            if (
                len(recent) >= FAILURE_THRESHOLD
                and ip not in alerted_ips
            ):
                window_start = recent[0]
                window_end = event_time

                message = (
                    f"HIGH RISK: {ip} had at least "
                    f"{len(recent)} failed logins within "
                    f"{TIME_WINDOW_MINUTES} minutes."
                )

                alerts.append(message)
                alerted_ips.add(ip)

                save_alert(
                    ip,
                    len(recent),
                    window_start,
                    window_end,
                    message,
                )

    # Display the current security report
    print("\n===== SECURITY MONITORING REPORT =====")
    print(f"Total login events: {total_events}")
    print(f"Successful logins: {successful_logins}")
    print(f"Failed login events: {sum(failed_attempts.values())}")

    print("\nFailed login attempts by IP:")
    for ip, count in failed_attempts.most_common():
        print(f"{ip}: {count}")

    print("\n===== TIME-BASED SECURITY ALERTS =====")
    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("No threshold breaches detected.")

    # Save the current run's report
    with REPORT_FILE.open("w", encoding="utf-8") as report:
        report.write("SECURITY MONITORING ALERT REPORT\n")
        report.write("================================\n\n")

        if alerts:
            report.write("\n".join(alerts) + "\n")
        else:
            report.write("No threshold breaches detected.\n")

    print(f"\nCurrent report saved to: {REPORT_FILE}")
    print(f"Alert history saved to: {HISTORY_FILE}")


if __name__ == "__main__":
    try:
        analyze_logs()
    except (OSError, csv.Error, ValueError) as error:
        print(f"Error processing security logs: {error}")
