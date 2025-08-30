from datetime import datetime, timedelta
from collections import defaultdict, deque
from urllib.parse import unquote, urlsplit

suspicious_events = []
list_of_ips = defaultdict(int)

error_burst_window = defaultdict(deque)
uniq_404_403_window = defaultdict(deque)
login_fail_window = defaultdict(deque)
fail_window = defaultdict(deque)
req_window = defaultdict(deque)
WINDOW = timedelta(minutes=10)
LOGIN_PATH_HINTS = (
    "login", "signin", "auth", "oauth", "account", "session", "wp-login.php", "/xmlrpc.php"
)
TRAVERSAL = (
    "../", "..\\", "%2e%2e%2f", "%2e%2e%5c", "..%2f", "..%5c"
)
LFI = (
    "etc/passwd", "proc/self/environ", "windows/win.ini", "php://", "file://", "expect://"
)
SECRETS = (
    "/.env", "/.git", "/.svn/entries", "/config.php", "/web-inf/web.xml", "/server-status"
)
CLOUD_META = (
    "169.254.169.254", "/latest/meta-data", "computemetadata/"
)
JNDI = (
    "${jndi:",
)
SPRING_ACT = (
    "/actuator/env", "/actuator/heapdump", "/actuator/loggers"
)
WORDPRESS = (
    "/xmlrpc.php", "/wp-json/wp/v2/users", "/?author="
)
DANG_METHODS = (
    "TRACE", "TRACK", "DEBUG",
    "PROPFIND", "MKCOL", "MOVE", "COPY", "SEARCH",
    "PUT", "DELETE"
)
SQLI_PATTERNS = (
    "' or '1'='1", "' or 1=1 --", "union select", "union all select", "information_schema", "sleep(", "benchmark(", 
    "waitfor delay", "extractvalue", "updatexml", "--", "/*"
)
CMDINJ_PATTERNS = (
    ";wget", ";curl", "|bash", "&&", "`", "$(", "|sh", ";nc", "powershell", "cmd.exe"
)

def is_login_endpoint(p_norm: str) -> bool:
    return any(h in p_norm for h in LOGIN_PATH_HINTS)

def normalize_http_fields(e: dict):
    p = (e.get("path") or "")
    u = (e.get("user_agent") or "")
    m = (e.get("method") or "")

    try:
        p = unquote(unquote(p))
    except Exception:
        pass

    e["_path_norm"] = p.lower()
    e["_ua_norm"] = u.lower()
    e["_method_norm"] = m.upper()
    return e

def extract_query_lower(path_norm: str) -> str:
    try:
        return (urlsplit(path_norm).query or "").lower()
    except Exception:
        return ""

def extract_client_ip(e: dict) -> str:
    ip = e.get("ip", "N/A")
    xff = e.get("x_forwarded_for") or e.get("X-Forwarded-For")
    if xff:
        for cand in str(xff).split(","):
            cand = cand.strip()
            if cand and cand.lower() not in ("unknown", "-"):
                ip = cand
                break
    e["_client_ip"] = ip
    return ip

def parse_apache_dt(date_field: str):
    if not date_field or date_field == "N/A":
        return None
    s = date_field.strip("[]")
    try:
        return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")
    except Exception:
        return None
    
def canonicalize_path(p: str) -> str:
    if p and p != "/" and p.endswith("/"):
        return p[:-1]
    return p

def push_prune_and_count_unique(dq: deque, now_dt: datetime, value: str, window: timedelta = WINDOW):
    cutoff = now_dt - window
    while dq and dq[0][0] < cutoff:
        dq.popleft()
    dq.append((now_dt, value))
    return len({v for _, v in dq})

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

        if access_log_parsed["severity"] == "CRITICAL":
            return access_log_parsed

        if access_log_parsed["severity"] == "high":
            access_log_parsed["severity"] = "CRITICAL"
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

    if not access_log_parsed:
        return suspicious_events

    now_dt = parse_apache_dt(access_log_parsed.get("date"))

    access_log_parsed = normalize_http_fields(access_log_parsed)
    extract_client_ip(access_log_parsed)

    client_ip = access_log_parsed.get("_client_ip") or access_log_parsed.get("ip", "N/A")
    p_norm = access_log_parsed.get("_path_norm", "")
    q_norm = extract_query_lower(p_norm)
    
    req_count_10m = push_and_prune(req_window[client_ip], now_dt)

    line_appended = False
    def append_once(e):
        nonlocal line_appended
        if not line_appended:
            suspicious_events.append(e)
            line_appended = True

    if access_log_parsed:
        for key in access_log_parsed:
            if key == "status":

                s = access_log_parsed["status"]
                if s in ("401", "403") and is_login_endpoint(p_norm):
                    fails_login_10m = push_and_prune(login_fail_window[client_ip], now_dt)
                    if fails_login_10m > 3:
                        higher_severity(access_log_parsed)
                        reason = [f"login fails on auth endpoint (10m): {fails_login_10m}"]
                        add_severity_reason(access_log_parsed, reason)
                        mitre_id = ["T1110"]
                        add_mitre_id(access_log_parsed, mitre_id)
                        append_once(access_log_parsed)
                    if fails_login_10m > 6:
                        higher_severity(access_log_parsed)
                        reason = ["heavy login brute (auth endpoint)"]
                        add_severity_reason(access_log_parsed, reason)
                        append_once(access_log_parsed)

                if access_log_parsed["status"] == "404" or access_log_parsed["status"] == "401" or access_log_parsed["status"] == "403":
                    
                    list_of_ips[client_ip] += 1

                    fails_10m = push_and_prune(fail_window[client_ip], now_dt)

                    if fails_10m > 2:
                        higher_severity(access_log_parsed)
                        reason = ["HTTP error burst - more than 2 attempts (10m window)"]
                        add_severity_reason(access_log_parsed, reason)
                        access_log_parsed["404/401/403_attempts"] = fails_10m
                        mitre_id = ["T1595.002", "T1190"]
                        add_mitre_id(access_log_parsed, mitre_id)
                        append_once(access_log_parsed)

                    if fails_10m > 4:
                        higher_severity(access_log_parsed)
                        reason = ["HTTP error burst - more than 4 attempts (10m window)"]
                        add_severity_reason(access_log_parsed, reason)
                        access_log_parsed["404/401/403_attempts"] = fails_10m
                        append_once(access_log_parsed)

                    if fails_10m > 9:
                        higher_severity(access_log_parsed)
                        reason = ["HTTP error burst - more than 9 attempts (10m window)"]
                        add_severity_reason(access_log_parsed, reason)
                        access_log_parsed["404/401/403_attempts"] = fails_10m
                        append_once(access_log_parsed)

                    if req_count_10m > 99:
                        higher_severity(access_log_parsed)
                        reason = [f"high request rate per IP (10m window): {req_count_10m}"]
                        add_severity_reason(access_log_parsed, reason)
                        mitre_id = ["T1595", "T1498.001"]
                        add_mitre_id(access_log_parsed, mitre_id)
                        append_once(access_log_parsed)

                    if s in ("404", "403"):
                        p_canon = canonicalize_path(p_norm)
                        uniq_cnt = push_prune_and_count_unique(uniq_404_403_window[client_ip], now_dt, p_canon)
                        if uniq_cnt >= 15:
                            higher_severity(access_log_parsed)
                            reason = [f"enumeration burst: {uniq_cnt} distinct 404/403 (10m)"]
                            add_severity_reason(access_log_parsed, reason)
                            mitre_id = ["T1595.001"]
                            add_mitre_id(access_log_parsed, mitre_id)
                            access_log_parsed["distinct_not_found_10m"] = uniq_cnt
                            append_once(access_log_parsed)
                    
                    if s in ("404", "403"):
                        errors_10m = push_and_prune(error_burst_window[client_ip], now_dt)
                        if errors_10m >= 10:
                            higher_severity(access_log_parsed)
                            reason = [f"HTTP error burst (404/403) - enumeration (10m): {errors_10m}"]
                            add_severity_reason(access_log_parsed, reason)
                            mitre_id = ["T1595.001"]
                            add_mitre_id(access_log_parsed, mitre_id)
                            append_once(access_log_parsed)

            if key == "path":
                suspicious_URls = ["phpmyadmin", "/etc/passwd", "/wp-login.php", "/admin", "/env", "/wp-admin", "/server-status", "/.git", "/config.php"]
                if any(url in access_log_parsed["path"] for url in suspicious_URls):
                    higher_severity(access_log_parsed)
                    reason = ["suspicious URl"]
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1190"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    append_once(access_log_parsed)

                if any(p in q_norm for p in SQLI_PATTERNS):
                    higher_severity(access_log_parsed)
                    reason = ["SQLi pattern (query)"]
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1190"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    append_once(access_log_parsed)

                if any(p in p_norm for p in CMDINJ_PATTERNS) or any(p in q_norm for p in CMDINJ_PATTERNS):
                    higher_severity(access_log_parsed)
                    reason = ["command injection pattern"]
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1059"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    append_once(access_log_parsed)

                if any(x in p_norm for x in TRAVERSAL) or any(x in p_norm for x in LFI):
                    higher_severity(access_log_parsed)
                    reason = ["path traversal / LFI pattern"]
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1190"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    append_once(access_log_parsed)

                elif any(x in p_norm for x in SECRETS):
                    higher_severity(access_log_parsed)
                    reason = ["sensitive file / secret probe"]
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1595"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    append_once(access_log_parsed)

                elif any(x in p_norm for x in CLOUD_META):
                    higher_severity(access_log_parsed)
                    reason = ["cloud metadata access attempt"]
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1190"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    append_once(access_log_parsed)

                elif any(x in p_norm for x in JNDI):
                    higher_severity(access_log_parsed)
                    reason = ["JNDI lookup pattern (Log4Shell-style)"]
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1190"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    append_once(access_log_parsed)

                elif any(x in p_norm for x in SPRING_ACT) or any(x in p_norm for x in WORDPRESS):
                    higher_severity(access_log_parsed)
                    reason = ["well-known framework endpoint probe"]
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1595"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    append_once(access_log_parsed)

            if key == "user_agent":
                anomalous_ua = ["curl", "python-requests", "sqlmap", "nikto"]
                if any(ua in access_log_parsed["_ua_norm"] for ua in anomalous_ua):
                    higher_severity(access_log_parsed)
                    reason = ["anomalous user-agent (potential scanner)"]
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1595", "T1036.005"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    append_once(access_log_parsed)

            
            if key == "method":
                strange_method = ["TRACE", "TRACK", "DEBUG", "CONNECT"]
                if any(method == access_log_parsed["_method_norm"] for method in strange_method):
                    higher_severity(access_log_parsed)
                    reason = ["strange method"]
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1190"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    append_once(access_log_parsed)

                m = access_log_parsed.get("_method_norm", "")
                if any(m == dm for dm in DANG_METHODS):
                    higher_severity(access_log_parsed)
                    reason = [f"dangerous/rare HTTP method: {m}"]
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1190"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    append_once(access_log_parsed)

                    s = access_log_parsed.get("status", "")
                    if s and s.startswith("2"):
                        higher_severity(access_log_parsed)
                        reason = ["method enabled (2xx)"]
                        add_severity_reason(access_log_parsed, reason)
                        append_once(access_log_parsed)


                

        return suspicious_events
    else:
        return