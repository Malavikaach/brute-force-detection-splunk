# Security Monitoring and Brute-Force Attack Detection Using Splunk

## Project Overview
A beginner-friendly security monitoring project that detects suspicious login activity using Python and Splunk. It identifies IP addresses with repeated failed login attempts within a five-minute window and displays security alerts.

## Objectives
- Analyze login events from CSV logs.
- Detect potential brute-force activity.
- Generate risk-based alerts.
- Prevent duplicate alert-history entries.
- Visualize login activity in a Streamlit dashboard.
- Search and monitor events using Splunk Enterprise.

## Tools and Technologies
- Python
- Splunk Enterprise
- Streamlit
- Pandas
- CSV log files
- Python unittest

## Detection Logic
The detection rule flags an IP address when it has at least five failed login attempts within a five-minute interval.

## Project Components
- `detector.py` — analyzes login events and generates alerts.
- `dashboard.py` — displays login statistics and alert history.
- `login_logs.csv` — sample login events for testing.
- `test_detector.py` — automated tests for detection and duplicate prevention.
- `alert_history.csv` — recorded alert history.
- `alerts.txt` — generated security report.

## Testing
Seven automated unit tests passed, covering detection thresholds, time windows, timestamp ordering, and duplicate-alert prevention.

## Example Result
A simulated IP address, `192.168.1.10`, was flagged for repeated failed logins. Splunk also identified suspicious activity in its five-minute detection search.

## Important Note
This project currently uses simulated CSV login events for demonstration. It is a learning and portfolio project, not a production security monitoring system.

## Future Improvements
- Ingest live authentication logs.
- Add email notifications.
- Improve dashboard visualizations.
- Add more detection rules and severity levels.
- Automate log ingestion and testing.

## Skills Demonstrated
Log analysis, security event monitoring, brute-force detection, SPL queries, alert configuration, Python scripting, testing, and dashboard development.
