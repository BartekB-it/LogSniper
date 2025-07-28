def classify_access_log(log_entry):
    ua = log_entry["user_agent"].lower()
    ip = log_entry["ip"]
    path = log_entry["path"].lower()
    method = log_entry["method"]
    status = log_entry["status"]