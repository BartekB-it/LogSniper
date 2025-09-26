from src.analyzers.analyzer_access import analyze_access_log
from src.analyzers.analyzer_auth import analyze_auth_log
from src.analyzers.analyzer_evtx_new import analyze_evtx
from src.analyzers.analyzer_sys import analyze_sys_log
from src.analyzers.analyzer_sys_test import analyze_sys_log_test
import json
import xmltodict

log_type = input("Choose log type (access/auth/evtx/sys/test): ")

if log_type == "access":
    try:
        analyze_access_log("../../test_logs/access.log")
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
        evtx_path = "../../test_logs/Security.evtx"
        results = analyze_evtx(evtx_path)
        print(f"EVTX results: {json.dumps(results, indent=2)}")
    except FileNotFoundError:
        print("The specified file was not found.")
    except Exception as e:
        print(f"An error occured: {e}")
elif log_type == "sys":
    try:
        sys_path = "../../test_logs/syslog.log"
        analyze_sys_log(sys_path)
    except FileNotFoundError:
        print("The specified file was not found.")
    except Exception as e:
        print(f"An error occured: {e}")
else:
    print("Unknown log type.")