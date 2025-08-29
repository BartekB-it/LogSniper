from datetime import datetime, timedelta
from collections import defaultdict, deque

suspicious_events = []
list_of_ips = defaultdict(int)

invalid_window = defaultdict(deque)
user_fail_window = defaultdict(deque)
root_fail_window = defaultdict(deque)
fail_window = defaultdict(deque)
req_window = defaultdict(deque)

WINDOW = timedelta(minutes=10)
ALLOWED_PREFIXES = ["10.", "192.168.", "172.16."]
    
def parse_syslog_ts(ts:str):
    if not ts or ts == "N/A":
        return None
    try:
        year = datetime.now().year
        return datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")
    except Exception:
        return None

def prune_only(dq: deque, now_dt: datetime, window: timedelta = WINDOW):
    if now_dt is None:
        return len(dq)
    cutoff = now_dt - window
    while dq and dq[0] < cutoff:
        dq.popleft()
    return len(dq)

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

        if auth_log_parsed["severity"] == "CRITICAL":
            return auth_log_parsed

        if auth_log_parsed["severity"] == "high":
            auth_log_parsed["severity"] = "CRITICAL"
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
            auth_log_parsed["severity_reason"] = []
        for r in (severity_reason if isinstance(severity_reason, list) else [severity_reason]):
            if r not in auth_log_parsed["severity_reason"]:
                auth_log_parsed["severity_reason"].append(r)
        return auth_log_parsed

    def add_mitre_id(auth_log_parsed, mitre_id):
        if auth_log_parsed["mitre_id"] == "N/A":
            auth_log_parsed["mitre_id"] = []
        for m in (mitre_id if isinstance(mitre_id, list) else [mitre_id]):
            if m not in auth_log_parsed["mitre_id"]:
                auth_log_parsed["mitre_id"].append(m)
        return auth_log_parsed

    if not auth_log_parsed:
        return suspicious_events
    ip = auth_log_parsed.get("ip", "N/A")
    now_dt = parse_syslog_ts(auth_log_parsed.get("timestamp"))
    req_count_10m = push_and_prune(req_window[ip], now_dt)

    if ip and ip != "N/A" and not any(ip.startswith(p) for p in ALLOWED_PREFIXES):
        reason = [f"source outside allowlist subnets ({ip})"]
        add_severity_reason(auth_log_parsed, reason)
        mitre_id = ["T1021.004"]
        add_mitre_id(auth_log_parsed, mitre_id)

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
                        reason = [f"high connection/auth rate per IP (10m window): {req_count_10m}"]
                        add_severity_reason(auth_log_parsed, reason)
                        mitre_id = ["T1595", "T1498.001"]
                        add_mitre_id(auth_log_parsed, mitre_id)
                        append_once(auth_log_parsed)

                    username = auth_log_parsed.get("username")
                    if username and username != "N/A" and auth_log_parsed.get("user") != "Invalid user":
                        user_key = (ip, auth_log_parsed.get("user", "N/A"))
                        user_fails_10m = push_and_prune(user_fail_window[user_key], now_dt)

                        if user_fails_10m > 4:
                            higher_severity(auth_log_parsed)
                            reason = ["targeted user brute attempts (10m window)"]
                            add_severity_reason(auth_log_parsed, reason)
                            mitre_id = ["T1110"]
                            add_mitre_id(auth_log_parsed, mitre_id)
                            auth_log_parsed["login_attempts_user"] = user_fails_10m
                            append_once(auth_log_parsed)

                if auth_log_parsed["password"] == "Accepted password":
                    fails_10m_now = prune_only(fail_window[ip], now_dt)
                    if fails_10m_now > 4:
                        if auth_log_parsed["severity"] == "CRITICAL":
                            auth_log_parsed["severity"] = "CRITICAL"
                        else:
                            auth_log_parsed["severity"] = "high"
                        reason = ["accepted password after brute force (warning!)"]
                        add_severity_reason(auth_log_parsed, reason)
                        auth_log_parsed["login_attempts"] = fails_10m_now
                        mitre_id = ["T1110", "T1078"]
                        add_mitre_id(auth_log_parsed, mitre_id)
                        append_once(auth_log_parsed)

            if key == "user":
                if auth_log_parsed["user"] == "Invalid user":
                    invalid_10m = push_and_prune(invalid_window[ip], now_dt)
                    higher_severity(auth_log_parsed)
                    reason = ["invalid user"]
                    add_severity_reason(auth_log_parsed, reason)
                    mitre_id = ["T1087.001"]
                    add_mitre_id(auth_log_parsed, mitre_id)
                    auth_log_parsed["invalid_user_attempts"] = invalid_10m
                    
                    if invalid_10m > 4:
                        higher_severity(auth_log_parsed)
                        reason = ["invalid user burst (10m window)"] 
                        add_severity_reason(auth_log_parsed, reason)
                        
                    append_once(auth_log_parsed)

                if auth_log_parsed["user"] == "root" and auth_log_parsed["password"] == "Failed password":
                    reason = ["root login attempt"]
                    add_severity_reason(auth_log_parsed, reason)
                    append_once(auth_log_parsed)
                    
                if auth_log_parsed["user"] == "root" and auth_log_parsed["password"] == "Accepted password":
                    reason = ["root login success"]
                    add_severity_reason(auth_log_parsed, reason)
                    mitre_id = ["T1078"]
                    add_mitre_id(auth_log_parsed, mitre_id)
                    append_once(auth_log_parsed)

                if auth_log_parsed["user"] == "root" and auth_log_parsed.get("password") == "Failed password":
                    root_fails_10m = push_and_prune(root_fail_window[ip], now_dt)
                    reason = ["root login attempt"]
                    add_severity_reason(auth_log_parsed, reason)
                    if root_fails_10m > 2:
                        higher_severity(auth_log_parsed)
                        reason = ["root brute burst (10m window)"]
                        mitre_id = ["T1110"]
                        add_mitre_id(auth_log_parsed, mitre_id)
                    append_once(auth_log_parsed)

        return suspicious_events
    else:
        return
