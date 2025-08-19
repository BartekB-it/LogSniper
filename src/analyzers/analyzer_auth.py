import os
import json
from src.parsers.parser_auth import parse_log_line_auth
from src.rules.rules_auth import classify_auth_log, suspicious_events, list_of_ips

os.chdir(os.path.dirname(__file__))

def analyze_auth_log(auth_path):
    with open (auth_path, "r") as file:
        for line in file:
            auth_log_parsed = parse_log_line_auth(line)
            classify_auth_log(auth_log_parsed)
    
        for log in suspicious_events:
            print(log)

        print(f"\nFound {len(suspicious_events)} events. Saved to suspicious_events_auth.json")

        sorted_list_of_ips = dict(sorted(list_of_ips.items(), key=lambda item: item[1], reverse=True))

        suspicious_events.append(sorted_list_of_ips)

        print(f"Here's a ranking of suspicious ips with sums of their attempts to login:\n{sorted_list_of_ips}")

        with open("../../results/suspicious_events_auth.json", "w") as f:
            json.dump(suspicious_events, f, indent=2)

        print("The list was added to the 'suspicious_events_auth.json' at the end - as a summary")

    return suspicious_events