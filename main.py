import os
from analyzers.access import analyze_access_log
from analyzers.auth import analyze_auth_log

os.chdir(os.path.dirname(__file__))

log_type = input("Choose log type (access/auth): ")

if log_type == "access":
    analyze_access_log("logs/apache_shady.log")
elif log_type == "auth":
    analyze_auth_log("logs/auth.log")
else:
    print("Unknown log type.")
