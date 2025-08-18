import json
from src.rules.rules_sys import classify_sys_log, suspicious_events, list_of_ips, worth_noting_events
from src.parsers.parser_sys import parser_sys_log

def analyze_sys_log(sys_path):
    with open(sys_path, "r") as file:
        for line in file:
            sys_log_parsed = parser_sys_log(line)
            classify_sys_log(sys_log_parsed)
        for log in suspicious_events:
            print(log)

        print(f"We've found {len(worth_noting_events)} events worth noting (severity: info). Results were saved to: 'worth_noting_events_syslog.json'")
        print(f"We've found {len(suspicious_events)} suspicious events. Results were saved to 'suspicious_events_syslog.json'")

        sorted_list_of_ips = dict(sorted(list_of_ips.items(), key=lambda item: item[1], reverse=True))

        suspicious_events.append(sorted_list_of_ips)

        print(f"Here's a ranking of suspicious ips with sums of their attempts to login:\n{sorted_list_of_ips}")

        with open("../../results/worth_noting_events_syslog.json", "w") as f:
            json.dump(worth_noting_events, f, indent=2)

        with open("../../results/suspicious_events_syslog.json", "w") as f:
            json.dump(suspicious_events, f, indent=2)

        print("The list was added to the 'suspicious_events_syslog.json' at the end - as a summary.")


#    list_of_attempts = list(list_of_ips.values())
#    list_of_ranks = sorted(list(list_of_ips.values()), reverse=True)

#    print(list_of_attempts)
#    print(list_of_ranks)
#    print(list_of_ips)

        
    