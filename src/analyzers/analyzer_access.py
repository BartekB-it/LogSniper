import os
import json
from collections import defaultdict
from src.parsers.parser_access import parse_log_line
from src.rules.rules_access import classify_access_log, ip_404_counter#, url_ip_map

os.chdir(os.path.dirname(__file__))

def analyze_access_log(log_path):

    classified_entries = []

    with open (log_path, "r") as file:
        for line in file:
            log_entry = parse_log_line(line)

            if log_entry["status"] == "404":
                ip_404_counter[log_entry["ip"]] += 1

#            url_ip_map[log_entry["path"]].add(log_entry["ip"])

            classification = classify_access_log(log_entry)
            log_entry["classification"] = classification

            if classification != "NORMAL":
                classified_entries.append(log_entry)

            print(f'[{classification}] IP: {log_entry["ip"]}, Date: {log_entry["date"]}, Method: {log_entry["method"]}, Path: {log_entry["path"]} Status: {log_entry["status"]} User Agent: {log_entry["user_agent"]}')

    with open("../../results/suspicious_entries_access.json", "w") as f:
        json.dump(classified_entries, f, indent=2)

    print(f"\nFound {len(classified_entries)} classified entries. Saved to suspicious_entries_access.json")

    return classified_entries
