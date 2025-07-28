import os
import json
from collections import defaultdict
from parser_access import parse_log_line
from rules_access import classify_access_log, ip_404_counter, url_ip_map

os.chdir(os.path.dirname(__file__))

classified_entries = []

with open ("../logs/apache_shady.log", "r") as file:
    for line in file:
        log_entry = parse_log_line(line)

        if log_entry["status"] == "404":
            ip_404_counter[log_entry["ip"]] += 1

        url_ip_map[log_entry["path"]].add(log_entry["ip"])

with open("../logs/apache_shady.log", "r") as file:
    for line in file:
        log_entry = parse_log_line(line)
        classification = classify_access_log(log_entry)
        log_entry["classification"] = classification

        if classification != "NORMAL":
            classified_entries.append(log_entry)

        print(f'[{classification}] IP: {log_entry["ip"]}, Date: {log_entry["date"]}, Method: {log_entry["method"]}, Path: {log_entry["path"]} Status:{log_entry["status"]} User Agent: {log_entry["user_agent"]}')

with open("suspicious_entries.json", "w") as f:
    json.dump(classified_entries, f, indent=2)

print(f"\nFound {len(classified_entries)} classified entries. Saved to suspicious_entries.json")
print("\n--- STATS ---")
print(f"Sum of unique IPs: {len(ip_404_counter)}")
print(f"Sum of unique paths: {len(url_ip_map)}")
