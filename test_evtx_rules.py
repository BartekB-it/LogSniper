# test_evtx_rules.py
import os
from datetime import datetime
from src.rules.rules_evtx import classify_evtx_log, suspicious_events

os.chdir(os.path.dirname(__file__))

# FAKE EVENT – should be detected
fake_event_service = {
    "Event": {
        "System": {
            "EventID": {"#text": "7045"},
            "TimeCreated": {"@SystemTime": "2025-07-30T12:00:00.000000Z"}
        },
        "EventData": {
            "Data": [
                {"@Name": "ServiceName", "#text": "EvilService"},
                {"@Name": "ServiceFileName", "#text": "C:\\Users\\Public\\evil.exe"},
                {"@Name": "ImagePath", "#text": "C:\\Users\\John\\AppData\\Local\\Temp\\bad.exe"}
            ]
        }
    }
}

# FAKE EVENT – shouldn't be detected
fake_event_normal = {
    "Event": {
        "System": {
            "EventID": {"#text": "4697"},
            "TimeCreated": {"@SystemTime": "2025-07-30T12:01:00.000000Z"}
        },
        "EventData": {
            "Data": [
                {"@Name": "ServiceName", "#text": "LegitService"},
                {"@Name": "ServiceFileName", "#text": "C:\\Program Files\\Legit\\legit.exe"},
                {"@Name": "ImagePath", "#text": "C:\\Program Files\\Legit\\legit.exe"}
            ]
        }
    }
}

suspicious_events.clear()

print("[TEST] Running T1543.003 detection test...")
classify_evtx_log(fake_event_service)
classify_evtx_log(fake_event_normal)

print("\nDetected suspicious events:")
for event in suspicious_events:
    print(event)

if not suspicious_events:
    print("No suspicious events detected.")

# --- TEST T1548: Abuse Elevation Control Mechanism (4688) ---
from src.rules.rules_evtx import classify_evtx_log, suspicious_events

# FAKE EVENT 1 – should be detected
fake_event_cmd = {
    "Event": {
        "System": {
            "EventID": {"#text": "4688"},
            "TimeCreated": {"@SystemTime": "2025-07-30T15:00:00.000000Z"}
        },
        "EventData": {
            "Data": [
                {"@Name": "NewProcessName", "#text": "C:\\Windows\\System32\\cmd.exe"},
                {"@Name": "CommandLine", "#text": "cmd.exe /c echo hello > \\\\pipe\\\\malicious"},
                {"@Name": "TargetUserName", "#text": "Attacker"},
                {"@Name": "ParentProcessName", "#text": "explorer.exe"}
            ]
        }
    }
}

# FAKE EVENT 2 – should be detected
fake_event_rundll = {
    "Event": {
        "System": {
            "EventID": {"#text": "4688"},
            "TimeCreated": {"@SystemTime": "2025-07-30T15:05:00.000000Z"}
        },
        "EventData": {
            "Data": [
                {"@Name": "NewProcessName", "#text": "C:\\Windows\\System32\\rundll32.exe"},
                {"@Name": "CommandLine", "#text": "rundll32.exe something.dll,a /p:evil"},
                {"@Name": "TargetUserName", "#text": "AdminUser"},
                {"@Name": "ParentProcessName", "#text": "services.exe"}
            ]
        }
    }
}

# FAKE EVENT 3 – shouldn't be detected
fake_event_normal_proc = {
    "Event": {
        "System": {
            "EventID": {"#text": "4688"},
            "TimeCreated": {"@SystemTime": "2025-07-30T15:10:00.000000Z"}
        },
        "EventData": {
            "Data": [
                {"@Name": "NewProcessName", "#text": "C:\\Program Files\\LegitApp\\legit.exe"},
                {"@Name": "CommandLine", "#text": "legit.exe /safe"},
                {"@Name": "TargetUserName", "#text": "NormalUser"},
                {"@Name": "ParentProcessName", "#text": "explorer.exe"}
            ]
        }
    }
}

suspicious_events.clear()

print("\n[TEST] Running T1548 (4688) detection test...")
classify_evtx_log(fake_event_cmd)
classify_evtx_log(fake_event_rundll)
classify_evtx_log(fake_event_normal_proc)

print("\nDetected suspicious events:")
for event in suspicious_events:
    print(event)

if not suspicious_events:
    print("No suspicious events detected.")