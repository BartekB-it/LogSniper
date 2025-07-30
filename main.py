from src.analyzers.analyzer_access import analyze_access_log
from src.analyzers.analyzer_auth import analyze_auth_log
from src.analyzers.analyzer_evtx import generate_report
from src.analyzers.analyzer_xml import generate_report_xml

log_type = input("Choose log type (access/auth/evtx): ")

if log_type == "access":
    analyze_access_log("logs/apache_shady.log")
elif log_type == "auth":
    analyze_auth_log("logs/auth.log")
elif log_type == "evtx":
    generate_report()
elif log_type == "xml":
    generate_report_xml()
else:
    print("Unknown log type.")
