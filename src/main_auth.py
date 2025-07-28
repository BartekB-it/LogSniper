import os
from collections import defaultdict
from parser_auth import parse_log_line_auth
from rules_auth import classify_auth_log, failed_attempts, BRUTE_FORCE_THRESHOLD

os.chdir(os.path.dirname(__file__))

with open ("../logs/auth.log", "r") as file:
    for line in file:
        log_entry_auth = parse_log_line_auth(line)

        classification = classify_auth_log(line)
        log_entry_auth["classification"] = classification
        alert = ""

        print(f"[{classification}] Time: {log_entry_auth["timestamp"]}, IP: {log_entry_auth["ip"]}, User: {log_entry_auth["user"]}")

        if classification == "FAILED_LOGIN" and log_entry_auth["ip"] != "N/A":
            failed_attempts[log_entry_auth["ip"]] += 1
            if failed_attempts[log_entry_auth["ip"]] == BRUTE_FORCE_THRESHOLD:
                alert = f"BRUTE FORCE DETECTED from {log_entry_auth["ip"]} after {BRUTE_FORCE_THRESHOLD} failed attempts"
                print(f"!!! {alert}")