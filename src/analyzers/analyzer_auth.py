import os
import json
from collections import defaultdict
from src.parsers.parser_auth import parse_log_line_auth
from src.rules.rules_auth import classify_auth_log, failed_attempts, BRUTE_FORCE_THRESHOLD
from geo_api import get_geolocation

os.chdir(os.path.dirname(__file__))

def extract_hour_from_log(log_entry):
    time = log_entry['time']
    hour = int(time.split(':')[0])
    return hour

suspicious_hours = [22, 23, 0, 1, 2, 3, 4, 5]

def is_suspicious_hour(hour):
    return hour in suspicious_hours

def analyze_auth_log(log_path):

    suspicious_entries = []

    with open (log_path, "r") as file:
        for line in file:
            log_entry_auth = parse_log_line_auth(line)

            ip = log_entry_auth['ip']

            geo_data = get_geolocation(ip)

            if geo_data:
                log_entry_auth['country'] = geo_data.get('country', 'N/A')
                log_entry_auth['region'] = geo_data.get('region', 'N/A')
                log_entry_auth['city'] = geo_data.get('city', 'N/A')
                log_entry_auth['timezone'] = geo_data.get('timezone', 'N/A')
            else:
                log_entry_auth['country'] = 'Unknown'
                log_entry_auth['region'] = 'Unknown'
                log_entry_auth['city'] = 'Unknown'
                log_entry_auth['timezone'] = 'Unknown'


            classification = classify_auth_log(line)
            log_entry_auth["classification"] = classification
            alert = ""

            print(f"[{classification}] Time: {log_entry_auth['timestamp']}, IP: {log_entry_auth['ip']}, User: {log_entry_auth['user']}, Country: {log_entry_auth["country"]}, Region: {log_entry_auth["region"]}, City: {log_entry_auth["city"]}, Timezone: {log_entry_auth["timezone"]}")

            if classification == "FAILED_LOGIN" and log_entry_auth["ip"] != "N/A":
                failed_attempts[log_entry_auth["ip"]] += 1
                if failed_attempts[log_entry_auth["ip"]] == BRUTE_FORCE_THRESHOLD:
                    alert = f"BRUTE FORCE DETECTED from {log_entry_auth["ip"]} after {BRUTE_FORCE_THRESHOLD} failed attempts"
                    print(f"!!! {alert}")
                    suspicious_entries.append(log_entry_auth)

            if classification == "SUCCESSFUL_LOGIN" or classification == "SUDO_USAGE":
                hour = extract_hour_from_log(log_entry_auth)
                if is_suspicious_hour(hour):
                    alert = f"Suspicious activity detected at: {log_entry_auth['timestamp']} (Time: {hour} [in hours])"
                    print(f"!!! {alert}")
                    log_entry_auth["alert"] = alert
                    suspicious_entries.append(log_entry_auth)

#            if classification != "NORMAL":
#                suspicious_entries.append(log_entry_auth)

    with open("../../results/suspicious_entries_auth.json", "w") as f:
        json.dump(suspicious_entries, f, indent=2)

    print(f"\nFound {len(suspicious_entries)} entries. Saved to suspicious_entries_auth.json")

    return suspicious_entries