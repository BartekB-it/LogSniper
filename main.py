from src.analyzers.analyzer_access import analyze_access_log
from src.analyzers.analyzer_auth import analyze_auth_log
from src.analyzers.analyzer_evtx import generate_report
from src.analyzers.analyzer_xml import generate_report_xml

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
        generate_report()
    except FileNotFoundError:
        print("The specified file was not found.")
    except Exception as e:
        print(f"An error occured: {e}")
elif log_type == "xml":
    try:
        generate_report_xml()
    except FileNotFoundError:
        print("The specified file was not found.")
    except Exception as e:
        print(f"An error occured: {e}")
else:
    print("Unknown log type.")
