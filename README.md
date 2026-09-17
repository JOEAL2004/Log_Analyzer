# Log Analyzer & Threat Detection Tool

A Python-based security tool that analyzes authentication logs and detects suspicious login activity.

## Features

- Reads authentication logs from a file
- Counts successful and failed login attempts
- Tracks failed login attempts by IP address
- Tracks failed login attempts by username
- Records the first failed attempt for each IP
- Detects IP addresses with repeated failed logins
- Detects usernames with repeated failed logins
- Detects IP addresses targeting multiple accounts
- Handles missing log files
- Handles malformed log entries
- Displays an analysis timestamp
- Uses configurable detection thresholds

## Detection Thresholds

The current thresholds are:

```python
failed_threshold = 3
multiple_user_threshold = 2