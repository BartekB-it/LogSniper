# test_evtx_rules.py
import os
from datetime import datetime
from src.rules.rules_evtx import classify_evtx_log, suspicious_events

os.chdir(os.path.dirname(__file__))

# FAKE EVENT – Service creation (7045) z podejrzanym AppData
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

# FAKE EVENT – Service creation (4697) w normalnej lokalizacji (nie powinien triggerować)
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

# Wyczyść stare wyniki (jeśli były)
suspicious_events.clear()

# Odpal testy
print("[TEST] Running T1543.003 detection test...")
classify_evtx_log(fake_event_service)
classify_evtx_log(fake_event_normal)

# Pokaż wyniki
print("\nDetected suspicious events:")
for event in suspicious_events:
    print(event)

if not suspicious_events:
    print("No suspicious events detected.")
