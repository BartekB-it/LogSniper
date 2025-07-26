import os
import re
os.chdir(os.path.dirname(__file__))

ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'

date_pattern = r'\[(.*?)\]'

method_pattern = r'\"(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)'

def classify_line(line):
    if "Failed password" in line:
        return "FAILED_LOGIN"
    elif "Accepted password" in line:
        return "SUCCESSFUL_LOGIN"
    elif "sudo" in line:
        return "SUDO_USAGE"
    else:
        return "UNKNOWN"

with open ("../logs/auth.log", "r") as file:
    for i, line in enumerate(file, 1):
        ip_match = re.search(ip_pattern, line)
        date_match = re.search(date_pattern, line)
        method_match = re.search(method_pattern, line)
        if ip_match and date_match and method_match:
            classification = classify_line(line)
            print(f"[{classification}] IP: {ip_match.group()}, Date: {date_match.group()}, Method: {method_match.group(1)}")