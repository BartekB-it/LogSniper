from src.analyzers.analyzer_access import analyze_access_log
from src.analyzers.analyzer_auth import analyze_auth_log
from src.analyzers.analyzer_evtx import generate_report
from src.rules.rules_evtx import classify_evtx_log, suspicious_events
from Evtx.Evtx import Evtx
import json
import xmltodict

log_type = input("Choose log type (access/auth/evtx): ")

if log_type == "access":
    try:
        analyze_access_log("../../test_logs/apache_shady.log")
    except FileNotFoundError:
        print("The specified file was not found.")
    except Exception as e:
        print(f"An error occured: {e}")
elif log_type == "auth":
    try:
        analyze_auth_log("../../test_logs/auth.log")
    except FileNotFoundError:
        print("The specified file was not found.")
    except Exception as e:
        print(f"An error occured: {e}")
elif log_type == "evtx":
    try:
        suspicious_events.clear()
        evtx_path = "../../test_logs/logon_fails_4625_evtx.evtx"
        with Evtx(evtx_path) as log:
            for record in log.records():
                xml = record.xml()
                data = xmltodict.parse(xml)
                classify_evtx_log(data)

        results = generate_report()
        print(f"EVTX results: {json.dumps(results, indent=2)}")
    except FileNotFoundError:
        print("The specified file was not found.")
    except Exception as e:
        print(f"An error occured: {e}")
else:
    print("Unknown log type.")