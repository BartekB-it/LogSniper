import re
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
    Create_or_Modify_System_Process_check (event)
    Abuse_Elevation_Control_Mechanism_check(event)

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
            "time_window_start": min(failed_attempts[key]).isoformat(),
            "time_window_end": max(failed_attempts[key]).isoformat()
        }

        suspicious_events.append(suspicious_events_step)

        failed_attempts[key] = [failed_attempts[key][-1]]

def Create_or_Modify_System_Process_check (event):

    service_file_name = extract_field(event["Event"]["EventData"]["Data"], "ServiceFileName")
    image_path = extract_field(event["Event"]["EventData"]["Data"], "ImagePath")
    binary_path = extract_field(event["Event"]["EventData"]["Data"], "BinaryPathName")
    service_name = extract_field(event["Event"]["EventData"]["Data"], "ServiceName")

    all_paths = [p for p in [service_file_name, image_path, binary_path] if p]

    if not all_paths:
        return

    timestamp_str = event["Event"]["System"]["TimeCreated"]["@SystemTime"]
    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")

    event_id = event["Event"]["System"]["EventID"]["#text"]
    if event_id not in ["4697", "7045"]:
        return

    match_found = any(re.search(r'(AppData|Public)', path, re.IGNORECASE) for path in all_paths)

    if match_found:
        suspicious_event_step = {
            "detection": "Create or Modify System Process (T1543.003)",
            "service_name": service_name or "N/A",
            "paths": all_paths,
            "timestamp": timestamp.isoformat()
        }
    

        suspicious_events.append(suspicious_event_step)

def Abuse_Elevation_Control_Mechanism_check(event):

    new_process_name = extract_field(event["Event"]["EventData"]["Data"], "NewProcessName")
    command_line = extract_field(event["Event"]["EventData"]["Data"], "CommandLine")
    target_user_name = extract_field(event["Event"]["EventData"]["Data"], "TargetUserName")
    parent_process_name = extract_field(event["Event"]["EventData"]["Data"], "ParentProcessName")

    timestamp_str = event["Event"]["System"]["TimeCreated"]["@SystemTime"]
    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")

    event_id = event["Event"]["System"]["EventID"]["#text"]
    if event_id != "4688":
        return
    
    cond_1 = re.search(r'(cmd\.exe|services\.exe)', new_process_name or '', re.IGNORECASE) and \
             re.search(r'(echo|\\pipe\\)', command_line or '', re.IGNORECASE)

    cond_2 = re.search(r'rundll32\.exe', new_process_name or '', re.IGNORECASE) and \
             re.search(r',a\s*/p:.*', command_line or '', re.IGNORECASE)

    if cond_1 or cond_2:
        suspicious_event_step = {
            "detection": "Abuse Elevation Control Mechanism (T1548)",
            "target_user_name": target_user_name or "N/A",
            "parent_process_name": parent_process_name or "N/A",
            "new_process_name": new_process_name or "N/A",
            "command_line": command_line or "N/A",
            "timestamp": timestamp.isoformat()
        }

        suspicious_events.append(suspicious_event_step)
        