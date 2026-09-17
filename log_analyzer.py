from datetime import datetime


def parse_log_line(line):
    # Extract the timestamp
    timestamp = line[:19]

    # Extract the username
    if "user=" in line:
        username = line.split("user=")[1].split(" ")[0]
    else:
        username = None

    # Extract the IP address
    if "ip=" in line:
      ip = line.split("ip=")[1].split(" ")[0]
    else:
        ip = None

    # Determine the login status
    if "LOGIN_FAILED" in line:
        status = "FAILED"
    elif "LOGIN_SUCCESS" in line:
        status = "SUCCESS"
    else:
        status = "UNKNOWN"

    return timestamp, username, ip, status

def record_failed_login(
    timestamp,
    username,
    ip,
    failed_by_ip,
    failed_by_user,
    first_failed_time,
    users_by_ip
):
    # Count failed attempts for the username
    if username in failed_by_user:
        failed_by_user[username] += 1
    else:
        failed_by_user[username] = 1

    # Create a set for this IP if it does not exist
    if ip not in users_by_ip:
        users_by_ip[ip] = set()

    # Record the username targeted by this IP
    users_by_ip[ip].add(username)

    # Store the first failed-login timestamp
    if ip not in first_failed_time:
        first_failed_time[ip] = timestamp

    # Count failed attempts for the IP
    if ip in failed_by_ip:
        failed_by_ip[ip] += 1
    else:
        failed_by_ip[ip] = 1

def log_analyzer():

    # Ask the user for the log file name
    file_name = input("Enter the log file name: ")

    # Try to open the log file
    try:
        with open(file_name, "r") as file:
            lines = file.readlines()

    except FileNotFoundError:
        print("Error: Log file not found.")
        return

    # Display report header
    print("\n" + "=" * 50)
    print("        LOG SECURITY ANALYSIS REPORT")
    print("=" * 50)

    # Record the time when the analysis was performed
    analysis_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("Analysis time:", analysis_time)

    # Counters and dictionaries
    failed_logins = 0
    successful_logins = 0

    first_failed_time = {}
    failed_by_ip = {}
    failed_by_user = {}
    users_by_ip = {}

    # Detection settings
    suspicious_activity = False
    suspicious_ip_found = False
    suspicious_user_found = False

    failed_threshold = 3
    multiple_user_threshold = 2

    # Analyze log entries
    for line in lines:

        timestamp, username, ip, status = parse_log_line(line)

        # Count successful logins
        if status == "SUCCESS":
            successful_logins += 1

        # Analyze failed login entries
        elif status == "FAILED":

            failed_logins += 1

            # Check whether the log entry contains an IP address
            if ip is None:
                print("Warning: IP address missing from the log entry")
                continue

            # Check whether the log entry contains a username
            if username is None:
                print("Warning: Username missing from the log entry")
                continue

            # Count failed attempts for each username
            record_failed_login(
            timestamp,
            username,
            ip,
            failed_by_ip,
            failed_by_user,
            first_failed_time,
            users_by_ip
            )

    # --------------------------------------------------
    # Suspicious IP activity
    # --------------------------------------------------

    print("\n" + "-" * 50)
    print("SUSPICIOUS IP ACTIVITY")
    print("-" * 50)

    for ip, count in failed_by_ip.items():

        if count >= failed_threshold:

            suspicious_activity = True
            suspicious_ip_found = True

            print(f"IP: {ip} -> {count} failed attempts")
            print(f"First failed attempt: {first_failed_time[ip]}")
            print(f"Targeted Users: {', '.join(sorted(users_by_ip[ip]))}")
            print("Status: Suspicious activity detected")
            print()

    if not suspicious_ip_found:
        print("No suspicious IP activity detected.")

    # --------------------------------------------------
    # Suspicious username activity
    # --------------------------------------------------

    print("\n" + "-" * 50)
    print("SUSPICIOUS USER ACTIVITY")
    print("-" * 50)

    for username, count in failed_by_user.items():

        if count >= failed_threshold:

            suspicious_user_found = True
            suspicious_activity = True

            print(f"Username: {username} -> {count} failed attempts")
            print("Status: Account may be under attack")

    if not suspicious_user_found:
        print("No suspicious user activity detected.")

    # --------------------------------------------------
    # Multiple-account targeting
    # --------------------------------------------------

    print("\n" + "-" * 50)
    print("MULTIPLE-ACCOUNT TARGETING")
    print("-" * 50)

    multiple_user_found = False

    for ip, users in users_by_ip.items():

        if len(users) >= multiple_user_threshold:

            multiple_user_found = True
            suspicious_activity = True

            print(f"IP: {ip} -> {len(users)} different users")
            print(
                f"Users targeted: "
                f"{', '.join(sorted(users))}"
            )
            print("Status: Multiple accounts targeted")

    if not multiple_user_found:
        print("No multiple-account targeting detected.")

    # --------------------------------------------------
    # Overall security status
    # --------------------------------------------------

    if suspicious_activity:
        print("\nSecurity Status: SUSPICIOUS ACTIVITY DETECTED")
    else:
        print("\nSecurity Status: No suspicious activity detected.")

    # --------------------------------------------------
    # Login summary
    # --------------------------------------------------

    print("\nLogin Summary")
    print("-------------")
    print("Total log entries:", len(lines))
    print("Successful logins:", successful_logins)
    print("Failed logins:", failed_logins)


# Start the log analyzer
log_analyzer()