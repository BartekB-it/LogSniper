import os
import re
import json
from collections import defaultdict

os.chdir(os.path.dirname(__file__))

ip_404_counter = defaultdict(int)
url_ip_map = defaultdict(set)
classified_entries = []

ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
date_pattern = r'\[(.*?)\]'
path_pattern = r'\"(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD) (.*?) HTTP/'
status_pattern = r'"\s(\d{3})\s'
user_agent_pattern = r'"[^"]*"$'

def classify_access_log(log_entry):
    ua = log_entry["user_agent"].lower()
    ip = log_entry["ip"]
    path = log_entry["path"].lower()
    method = log_entry["method"]
    status = log_entry["status"]

    if "sqlmap" in ua:
        return "SQLMAP_SCANNER"
    elif "nikto" in ua:
        return "NIKTO_SCANNER"
    elif "curl" in ua:
        return "CURL_SCANNER"
    elif "urllib" in ua and "PATCH" in method:
        return "POTENTIAL_API_MANIPULATION"
    elif "OPTIONS" in method or "HEAD" in method or "DELETE" in method:
        return "STRANGE_METHOD"
    elif "setup.cgi" in path:
        return "POTENTIAL_SETUP_CGI_SCANNER"
    elif "config.php" in path:
        return "POTENTIAL_CONFIG_PHP_SCANNER"
    elif "hidden" in path:
        return "POTENTIAL_SUSPICIOUS_PATH_SCANNER"
    elif status == "403" and path == "/login":
        return "POTENTIAL_BRUTEFORCE"
    elif ip_404_counter[ip] > 20:
        return "POTENTIAL_404_FLOOD"
    elif len(url_ip_map[path]) > 10:
        return "POTENTIAL_SCAN"
    else:
        return "NORMAL"

with open ("../logs/apache_shady.log", "r") as file:
    for i, line in enumerate(file, 1):
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

        log_entry = {
            "user_agent": user_agent,
            "path": path,
            "method": method,
            "status": status_code,
            "ip": ip,
            "date": date,
        }

        if status_code == "404":
            ip_404_counter[ip] += 1

        url_ip_map[path].add(ip)

        classification = classify_access_log(log_entry)
        log_entry["classification"] = classification

        if classification != "NORMAL":
            classified_entries.append(log_entry)

        print(f"[{classification}] IP: {ip}, Date: {date}, Method: {method}, Path: {path} Status:{status_code} User Agent: {user_agent}")

with open("suspicious_entries.json", "w") as f:
    json.dump(classified_entries, f, indent=2)

    print (f"\n Found {len(classified_entries)} classified entries. Saved to suspicious_entries.json")
    print("\n--- STATS ---")
    print(f"Sum of unique IPs: {len(ip_404_counter)}")
    print(f"Sum of unique paths: {len(url_ip_map)}")