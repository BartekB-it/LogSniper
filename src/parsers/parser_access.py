import re

ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
date_pattern = r'\[(.*?)\]'
path_pattern = r'\"(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD) (.*?) HTTP/'
status_pattern = r'"\s(\d{3})\s'
user_agent_pattern = r'"[^"]*"$'

def parse_log_line(line):
    ip_match = re.search(ip_pattern, line)
    date_match = re.search(date_pattern, line)
    path_match = re.search(path_pattern, line)
    status_match = re.search(status_pattern, line)
    user_agent_match = re.search(user_agent_pattern, line)

    ip = ip_match.group() if ip_match else "N/A"
    date = date_match.group() if date_match else "N/A"
    method = path_match.group(1) if path_match else "N/A"
    path = path_match.group(2) if path_match else "N/A"
    status_code = status_match.group(1) if status_match else "N/A"
    user_agent = user_agent_match.group().strip('"') if user_agent_match else "N/A"

    return {
        "user_agent": user_agent,
        "path": path,
        "method": method,
        "status": status_code,
        "ip": ip,
        "date": date,
    }