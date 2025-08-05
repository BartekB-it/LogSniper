import os
import json
from collections import defaultdict
from src.parsers.parser_access import parse_log_line
from src.rules.rules_access import classify_access_log, ip_404_counter#, url_ip_map
from geo_api import get_geolocation
from email_notification import send_alert_report, send_analysis_report_access

os.chdir(os.path.dirname(__file__))

def analyze_access_log(log_path):

    classified_entries = []

    with open (log_path, "r") as file:
        for line in file:
            log_entry = parse_log_line(line)

            ip = log_entry['ip']

            geo_data = get_geolocation(ip)

            if geo_data:
                log_entry['country'] = geo_data.get('country', 'N/A')
                log_entry['region'] = geo_data.get('region', 'N/A')
                log_entry['city'] = geo_data.get('city', 'N/A')
                log_entry['timezone'] = geo_data.get('timezone', 'N/A')
            else:
                log_entry['country'] = 'Unknown'
                log_entry['region'] = 'Unknown'
                log_entry['city'] = 'Unknown'
                log_entry['timezone'] = 'Unknown'

            if log_entry['status'] == "404":
                ip_404_counter[log_entry['ip']] += 1

#            url_ip_map[log_entry["path"]].add(log_entry["ip"])

            classification = classify_access_log(log_entry)
            log_entry['classification'] = classification

            if classification != "NORMAL":
                classified_entries.append(log_entry)

            if classification == "POTENTIAL_BRUTEFORCE":
                send_alert_report()

            date = log_entry['date']
            method = log_entry['method']
            path = log_entry['path']
            status = log_entry['status']
            user_agent = log_entry['user_agent']
            country = log_entry['country']
            region = log_entry['region']
            city = log_entry['city']
            timezone = log_entry['timezone']

            print(f"[{classification}] IP: {ip}, Date: {date}, Method: {method}, Path: {path} Status: {status} User Agent: {user_agent}, Country: {country}, Region: {region}, City: {city}, Timezone: {timezone}")

    with open("../../results/suspicious_entries_access.json", "w") as f:
        json.dump(classified_entries, f, indent=2)

    send_analysis_report_access(classified_entries)

    print(f"\nFound {len(classified_entries)} classified entries. Saved to suspicious_entries_access.json")

    return classified_entries