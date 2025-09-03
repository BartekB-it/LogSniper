from collections import deque, defaultdict
from datetime import datetime, timedelta

suspicious_events = []

ufw_window_by_src = defaultdict(deque)
unique_dpt_by_src = defaultdict(deque)

WINDOW = timedelta(minutes=10)

def higher_severity(e):
    if e["severity"] == "CRITICAL":
        e["severity"] = "CRITICAL"
        return
    elif e["severity"] == "high":
        e["severity"] = "CRITICAL"
        return
    elif e["severity"] == "mid":
        e["severity"] = "high"
        return
    elif e["severity"] == "low":
        e["severity"] = "mid"
        return
    else:
        e["severity"] = "low"
        return
    
def add_severity_reason(e, reason):
    if e["severity_reason"] == "N/A":
        e["severity_reason"] = reason
        return
    else:
        e["severity_reason"] += reason
        return

def add_mitre(e, mitre):
    if e["mitre_id"] == "N/A":
        e["mitre_id"] = mitre
        return
    else:
        e["mitre_id"] += mitre
        return

def parse_syslog_dt(dt):
    year = datetime.now().year
    return datetime.strptime(f"{year} {dt}", "%Y %b %d %H:%M:%S")

def analyze_sys_log(e):

    def push_and_prune(dq: deque, now_dt: datetime, window: timedelta = WINDOW):
        if now_dt is None:
            return len(dq)
        cutoff = now_dt - window
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now_dt)
        return len(dq)

    def only_prune(dq: deque, now_dt: datetime, window: timedelta = WINDOW):
        if now_dt is None:
            return len(dq)
        cutoff = now_dt - window
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    line_appended = False
    def append_once(e):
        nonlocal line_appended
        if not line_appended:
            suspicious_events.append(e)
            line_appended = True

    ef = e["event_family"]
    ea = e["event_action"]

    if ef == "kernel" and e["event_action"]["src"] and e["event_action"]["dpt"] and e["event_action"]["proto"]:

        #UFW burst per SRC + port-scan (unique DPT)

        src = e["event_action"]["src"]
        dpt = e["event_action"]["dpt"]
        proto = e["event_action"]["proto"]

        now_dt = parse_syslog_dt(e["timestamp"])
        count_burst = push_and_prune(ufw_window_by_src[src], now_dt)

        if count_burst > 10:
            higher_severity(e)
            add_severity_reason(e, ["UFW burst more than 10 tries (10m)"])
            add_mitre(e, ["T1595.002"])
            append_once(e)
        if count_burst > 25:
            higher_severity(e)
            add_severity_reason(e, ["UFW burst more than 25 tries (10m)"])
            append_once(e)

    return e

