from datetime import datetime, timedelta
from collections import defaultdict, deque

suspicious_events = []
list_of_ips = defaultdict(int)

fail_window = defaultdict(deque)
req_window = defaultdict(deque)
WINDOW = timedelta(minutes=10)

def parse_apache_dt(date_field: str):
    if not date_field or date_field == "N/A":
        return None
    s = date_field.strip("[]")
    try:
        return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")
    except Exception:
        return None
    
def push_and_prune(dq: deque, now_dt: datetime, window: timedelta = WINDOW):
    if now_dt is None:
        return len(dq)
    cutoff = now_dt - window
    while dq and dq[0] < cutoff:
        dq.popleft()
    dq.append(now_dt)
    return len(dq)

def classify_auth_log(auth_log_parsed):

    def higher_severity(auth_log_parsed):

        if auth_log_parsed["severity"] == "high":
            return auth_log_parsed

        if auth_log_parsed["severity"] == "mid":
            auth_log_parsed["severity"] = "high"
            return auth_log_parsed

        if auth_log_parsed["severity"] == "low":
            auth_log_parsed["severity"] = "mid"
            return auth_log_parsed

        if auth_log_parsed["severity"] == "info":
            auth_log_parsed["severity"] = "low"
            return auth_log_parsed
        
    def add_severity_reason(auth_log_parsed, severity_reason):
        if auth_log_parsed["severity_reason"] == "N/A":
            auth_log_parsed["severity_reason"] = severity_reason
            return auth_log_parsed
        else:
            auth_log_parsed["severity_reason"] += severity_reason
            return auth_log_parsed

    def add_mitre_id(auth_log_parsed, mitre_id):
        if auth_log_parsed["mitre_id"] == "N/A":
            auth_log_parsed["mitre_id"] = mitre_id
            return auth_log_parsed
        else:
            auth_log_parsed["mitre_id"] += mitre_id
            return auth_log_parsed

    if not auth_log_parsed:
        return suspicious_events
    ip = auth_log_parsed.get("ip", "N/A")
    now_dt = parse_apache_dt(auth_log_parsed.get("date"))
    req_count_10m = push_and_prune(req_window[ip], now_dt)

    line_appended = False
    def append_once(e):
        nonlocal line_appended
        if not line_appended:
            suspicious_events.append(e)
            line_appended = True

    if auth_log_parsed:
        for key in auth_log_parsed:
            if key == "password":
                if auth_log_parsed["password"] == "Failed password":

                    if auth_log_parsed["ip"] in list_of_ips:
                        list_of_ips[auth_log_parsed["ip"]] += 1
                    else:
                        list_of_ips[auth_log_parsed["ip"]] = 1

                    fails_10m = push_and_prune(fail_window[ip], now_dt)

                    if fails_10m > 2:
                        higher_severity(auth_log_parsed)
                        reason = ["more than 2 failed login attempts (10m window)"]
                        add_severity_reason(auth_log_parsed, reason)
                        auth_log_parsed["login_attempts"] = fails_10m
                        mitre_id = ["T1110"]
                        add_mitre_id(auth_log_parsed, mitre_id)
                        append_once(auth_log_parsed)

                    if fails_10m > 4:
                        higher_severity(auth_log_parsed)
                        reason = ["more than 4 failed login attempts (10m window)"]
                        add_severity_reason(auth_log_parsed, reason)
                        auth_log_parsed["login_attempts"] = fails_10m
                        append_once(auth_log_parsed)

                    if fails_10m > 9:
                        higher_severity(auth_log_parsed)
                        reason = ["more than 9 failed login attempts (10m window)"]
                        add_severity_reason(auth_log_parsed, reason)
                        auth_log_parsed["login_attempts"] = fails_10m
                        append_once(auth_log_parsed)

                    if req_count_10m > 99:
                        higher_severity(auth_log_parsed)
                        reason = [f"high request rate per IP (10m window): {req_count_10m}"]
                        add_severity_reason(auth_log_parsed, reason)
                        mitre_id = ["T1595", "T1498.001"]
                        add_mitre_id(auth_log_parsed, mitre_id)
                        append_once(auth_log_parsed)
                
                if fails_10m > 4 and auth_log_parsed["password"] == "Accepted password":
                    auth_log_parsed["severity"] = "high"
                    reason = ["accepted password after brute force (warning!)"]
                    add_severity_reason(auth_log_parsed, reason)
                    auth_log_parsed["login_attempts"] = fails_10m
                    mitre_id = ["T1110.001", "T1078"]
                    add_mitre_id(auth_log_parsed, mitre_id)
                    append_once(auth_log_parsed)

            if key == "user":
                if auth_log_parsed["user"] == "Invalid user":
                    higher_severity(auth_log_parsed)
                    reason = ["invalid user"]
                    add_severity_reason(auth_log_parsed, reason)
                    mitre_id = ["T1087.001"]
                    add_mitre_id(auth_log_parsed, mitre_id)
                    append_once(auth_log_parsed)

            if key == "user":
                if auth_log_parsed["user"] == "root" and auth_log_parsed["password"] == "Failed password":
                    reason = ["root login attempt"]
                    add_severity_reason(auth_log_parsed, reason)
                    append_once(auth_log_parsed)
                    
            if key == "user":
                if auth_log_parsed["user"] == "root" and auth_log_parsed["password"] == "Accepted password":
                    reason = ["root login success"]
                    add_severity_reason(auth_log_parsed, reason)
                    mitre_id = ["T1078"]
                    add_mitre_id(auth_log_parsed, mitre_id)
                    append_once(auth_log_parsed)

        return suspicious_events
    else:
        return
