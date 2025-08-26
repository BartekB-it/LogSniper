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

def classify_access_log(access_log_parsed):

    def higher_severity(access_log_parsed):

        if access_log_parsed["severity"] == "high":
            return access_log_parsed

        if access_log_parsed["severity"] == "mid":
            access_log_parsed["severity"] = "high"
            return access_log_parsed

        if access_log_parsed["severity"] == "low":
            access_log_parsed["severity"] = "mid"
            return access_log_parsed

        if access_log_parsed["severity"] == "info":
            access_log_parsed["severity"] = "low"
            return access_log_parsed
        
    def add_severity_reason(access_log_parsed, severity_reason):
        if access_log_parsed["severity_reason"] == "N/A":
            access_log_parsed["severity_reason"] = severity_reason
            return access_log_parsed
        else:
            access_log_parsed["severity_reason"] += severity_reason
            return access_log_parsed

    def add_mitre_id(access_log_parsed, mitre_id):
        if access_log_parsed["mitre_id"] == "N/A":
            access_log_parsed["mitre_id"] = mitre_id
            return access_log_parsed
        else:
            access_log_parsed["mitre_id"] += mitre_id
            return access_log_parsed

    if not access_log_parsed:
        return suspicious_events
    ip = access_log_parsed.get("ip", "N/A")
    now_dt = parse_apache_dt(access_log_parsed.get("date"))
    req_count_10m = push_and_prune(req_window[ip], now_dt)

    line_appended = False
    def append_once(e):
        nonlocal line_appended
        if not line_appended:
            suspicious_events.append(e)
            line_appended = True

    if access_log_parsed:
        for key in access_log_parsed:
            if key == "status": #HTTP error burst - fuzzing / directory bruteforce
                if access_log_parsed["status"] == "404" or access_log_parsed["status"] == "401" or access_log_parsed["status"] == "403":
                    
                    if access_log_parsed["ip"] in list_of_ips:
                        list_of_ips[access_log_parsed["ip"]] += 1
                    else:
                        list_of_ips[access_log_parsed["ip"]] = 1

                    fails_10m = push_and_prune(fail_window[ip], now_dt)

                    if fails_10m > 2:
                        higher_severity(access_log_parsed)
                        reason = ["more than 2 failed login attempts (10m window)"]
                        add_severity_reason(access_log_parsed, reason)
                        access_log_parsed["404/401/403_attempts"] = fails_10m
                        mitre_id = ["T1595.002", "T1190"]
                        add_mitre_id(access_log_parsed, mitre_id)
                        append_once(access_log_parsed)

                    if fails_10m > 4:
                        higher_severity(access_log_parsed)
                        reason = ["more than 4 failed login attempts (10m window)"]
                        add_severity_reason(access_log_parsed, reason)
                        access_log_parsed["404/401/403_attempts"] = fails_10m
                        append_once(access_log_parsed)

                    if fails_10m > 9:
                        higher_severity(access_log_parsed)
                        reason = ["more than 9 failed login attempts (10m window)"]
                        add_severity_reason(access_log_parsed, reason)
                        access_log_parsed["404/401/403_attempts"] = fails_10m
                        append_once(access_log_parsed)

                    if req_count_10m > 99: #High request rate per IP -> could be DDoS / fuzzing
                        higher_severity(access_log_parsed)
                        reason = [f"high request rate per IP (10m window): {req_count_10m}"]
                        add_severity_reason(access_log_parsed, reason)
                        mitre_id = ["T1595", "T1498.001"]
                        add_mitre_id(access_log_parsed, mitre_id)
                        append_once(access_log_parsed)

            if key == "path": #suspicious URls
                suspicious_URls = ["phpmyadmin", "/etc/passwd", "/wp-login.php", "/admin", "/env", "/wp-admin", "/server-status", "/.git", "/config.php"]
                if any(url in access_log_parsed["path"] for url in suspicious_URls):
                    higher_severity(access_log_parsed)
                    reason = ["suspicious URl"]
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1190"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    append_once(access_log_parsed)

            if key == "path": #SQLi patterns
                SQL_injection = ["' OR 1=1 --", "' OR '1'='1", "union select", "UNION SELECT", "information_schema", "--", "/*", "%27", "%3B"]
                if any(inj in access_log_parsed["path"] for inj in SQL_injection):
                    higher_severity(access_log_parsed)
                    reason = ["SQLi pattern"]
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1190"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    append_once(access_log_parsed)

            if key == "path": #command injection patterns
                command_injection = [";wget", ";curl", "|bash", "&&", "`cmd`", "$()"]
                if any(inj in access_log_parsed["path"] for inj in command_injection):
                    higher_severity(access_log_parsed)
                    reason = ["command injection pattern"]
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1059"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    append_once(access_log_parsed)

            if key == "user_agent": #anomalous User-Agent
                anomalous_ua = ["curl", "python-requests", "sqlmap", "nikto"]
                if any(ua in access_log_parsed["user_agent"] for ua in anomalous_ua):
                    higher_severity(access_log_parsed)
                    reason = ["anomalous user-agent (potential scanner)"]
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1595", "T1036.005"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    append_once(access_log_parsed)

            if key == "method": #strange method
                strange_method = ["DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]
                if any(method in access_log_parsed["method"] for method in strange_method):
                    higher_severity(access_log_parsed)
                    reason = ["strange method"]
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1071.001", "T1190"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    append_once(access_log_parsed)

        return suspicious_events
    else:
        return