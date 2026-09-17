# Log Analyzer & Threat Detection Tool

A lightweight Python-based security tool that analyzes authentication logs and detects suspicious login activity.

## Overview

This project is a lightweight security log analysis tool written in Python.

It processes authentication log files and identifies patterns that may indicate suspicious login activity, such as repeated failed login attempts and attempts to access multiple user accounts from the same IP address.

The project was built to practice practical cybersecurity concepts including log analysis, basic threat detection, Python file handling, parsing, and security-focused reporting.

## Features

- Reads authentication logs from a file
- Counts successful login attempts
- Counts failed login attempts
- Tracks failed login attempts by IP address
- Tracks failed login attempts by username
- Records the first failed attempt for each IP address
- Detects IP addresses with repeated failed login attempts
- Detects usernames with repeated failed login attempts
- Detects IP addresses targeting multiple accounts
- Handles missing log files
- Handles malformed log entries
- Displays an analysis timestamp
- Uses configurable detection thresholds
- Generates a readable security analysis report

## Technologies Used

- Python 3
- Python Standard Library
- File handling
- Dictionaries
- Sets
- String parsing
- Exception handling

## How It Works

The analyzer reads each line of an authentication log and extracts:

- Timestamp
- Username
- IP address
- Login status

The information is then processed to identify repeated failed login attempts.

The tool currently checks three main types of suspicious activity:

### 1. Suspicious IP Activity

An IP address is flagged when it reaches the configured failed-login threshold.

Example:

```text
IP: 192.168.1.50 -> 6 failed attempts
First failed attempt: 2026-09-15 09:12:45
Targeted Users: admin, alice, bob, root
Status: Suspicious activity detected