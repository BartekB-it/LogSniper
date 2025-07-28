import re

timestamp_pattern = r'^[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}'
ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
user_pattern = r'(?:invalid user|user) (\w+)'

def parse_log_line_auth(line):
    timestamp_match = re.search(timestamp_pattern, line)
    ip_match = re.search(ip_pattern, line)
    user_match = re.search(user_pattern, line)
    
    timestamp = timestamp_match.group() if timestamp_match else "N/A"
    ip = ip_match.group() if ip_match else "N/A"
    user = user_match.group(1) if user_match else "N/A"

    return {
        "timestamp": timestamp,
        "ip": ip,
        "user": user
    }