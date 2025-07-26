import os
import re
import csv
from collections import defaultdict

os.chdir(os.path.dirname(__file__))

timestamp_pattern = r'^[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}'
ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
user_pattern = r'(?:invalid user|user) (\w+)'

def classify_line(line):
    if "Failed password" in line:
        return "FAILED_LOGIN"
    elif "Accepted password" in line:
        return "SUCCESSFUL_LOGIN"
    elif "sudo" in line:
        return "SUDO_USAGE"
    else:
        return "UNKNOWN"

failed_attempts = defaultdict(int)
BRUTE_FORCE_THRESHOLD = 5

input_file = "../logs/auth.log"

output_file = "../logs/results.csv"

with open (input_file, "r") as file, open(output_file, "w", newline='', encoding="utf-8") as csvfile:
    fieldnames = ["classification", "timestamp", "ip", "user", "alert"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    for i, line in enumerate(file, 1):
        timestamp_match = re.search(timestamp_pattern, line)
        ip_match = re.search(ip_pattern, line)
        user_match = re.search(user_pattern, line)

        classification = classify_line(line)
        timestamp = timestamp_match.group() if timestamp_match else "N/A"
        ip = ip_match.group() if ip_match else "N/A"
        user = user_match.group(1) if user_match else "N/A"
        alert = ""

        print(f"[{classification}] Time: {timestamp}, IP: {ip}, User: {user}")

        if classification == "FAILED_LOGIN" and ip != "N/A":
            failed_attempts[ip] += 1
            if failed_attempts[ip] == BRUTE_FORCE_THRESHOLD:
                alert = f"BRUTE FORCE DETECTED from {ip} after {BRUTE_FORCE_THRESHOLD} failed attempts"
                print(f"!!! {alert}")

        writer.writerow({
            "classification": classification,
            "timestamp": timestamp,
            "ip": ip,
            "user": user,
            "alert": alert
        })