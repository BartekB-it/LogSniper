import os
import json
from src.parsers.parser_access import parse_log_line_access
from src.rules.rules_access import classify_access_log, suspicious_events, list_of_ips

os.chdir(os.path.dirname(__file__))

def analyze_access_log(access_path):
    with open (access_path, "r") as file:
        for line in file:
            access_log_parsed = parse_log_line_access(line)
            classify_access_log(access_log_parsed)

        for log in suspicious_events:
            print(log)

        print(f"\nFound {len(suspicious_events)} events. Saved to suspicious_events_access.json\n")

        sorted_list_of_ips = dict(sorted(list_of_ips.items(), key=lambda item: item[1], reverse=True))                

        print(f"Here's a ranking of suspicious ips with sums of their attempts to login:\n{sorted_list_of_ips}")

        with open("../../results/suspicious_events_access.json", "w") as f:
            json.dump(suspicious_events, f, indent=2)

        print("The list was added to the 'suspicious_events_access.json' at the end - as a summary")

    return suspicious_events