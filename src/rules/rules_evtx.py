from datetime import datetime, timedelta

suspicious_events = []
failed_attempts = {}

def extract_field(data_list, field_name):
    for entry in data_list:
        if entry ["@Name"] == field_name:
            return entry.get("#text")
    return None

def classify_evtx_log(event):
    Brute_Force_check(event)

def Brute_Force_check(event):
    timestamp_str = event["Event"]["System"]["TimeCreated"]["@SystemTime"]
    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")

    event_id = event["Event"]["System"]["EventID"]["#text"]
    if event_id not in ["4625", "5379"]:
        return

    ip = extract_field(event["Event"]["EventData"]["Data"], "IpAddress")
    account = extract_field(event["Event"]["EventData"]["Data"], "TargetUserName")
    if not ip or not account:
        return
        
    key = (ip, account)
    failed_attempts.setdefault(key, []).append(timestamp)

    failed_attempts[key] = [
        t for t in failed_attempts[key]
        if(timestamp - t).total_seconds() <= 60
    ]

    if len(failed_attempts[key]) >= 3:
        suspicious_events_step = {
            "detection": "Brute Force (T1110)",
            "ip": ip,
            "account": account,
            "attempts": len(failed_attempts[key]),
            "time_widnow_start": min(failed_attempts[key]),
            "time_window_end": max(failed_attempts[key])
        }

        suspicious_events.append(suspicious_events_step)

        failed_attempts[key] = [failed_attempts[key][-1]]
        
        