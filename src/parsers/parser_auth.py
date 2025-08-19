import re

hours_pattern = r'\d{2}:'
time_pattern = r'\d{2}:\d{2}:\d{2}'
timestamp_pattern = r'^[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}'
ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
user_pattern = r'for\s(\w){1,}\sfrom'
#user_pattern = r'(?:invalid user|user) (\w+)'
password_pattern = r'\s(\w){1,}\spassword'

def parse_log_line_auth(line):
    timestamp_match = re.search(timestamp_pattern, line)
    ip_match = re.search(ip_pattern, line)
    user_match = re.search(user_pattern, line)
    time_match = re.search(time_pattern, line)
    hours_match = re.search(hours_pattern, line)
    password_match = re.search(password_pattern, line)
    
    timestamp = timestamp_match.group() if timestamp_match else "N/A"
    ip = ip_match.group() if ip_match else "N/A"
    user = user_match.group() if user_match else "N/A"
    time = time_match.group() if time_match else "N/A"
    hours = hours_match.group() if hours_match else "N/A"
    password = password_match.group().strip() if password_match else "N/A"

    auth_log_parsed = {
        "password": password,
        "login_attempts": "N/A",
        "timestamp": timestamp,
        "ip": ip,
        "user": user,
        "time": time,
        "hours": hours
    }

    return auth_log_parsed