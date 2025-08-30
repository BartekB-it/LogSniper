from datetime import datetime, timedelta
from collections import defaultdict, deque

WINDOW = timedelta(minutes=10)
SHORT_WINDOW = timedelta(minutes=2)

suspicious_events = []

fail_by_src = defaultdict(deque)
fail_by_src_user = defaultdict(deque)

last_logon = {}
known_sources = defaultdict(set)

krb_fail_by_src = defaultdict(deque)
krb_fail_by_src_user = defaultdict(deque)
known_krb_sources = defaultdict(set)

ntlm_fail_by_ws_user = defaultdict(deque)
known_ntlm_workstations = defaultdict(set)

known_smb_sources = defaultdict(set)
SENSITIVE_SHARES = ("admin$", "c$", "ipc$")

SENSITIVE_GROUPS = {
    "Administrators", "Domain Admins", "Enterprise Admins",
    "Remote Desktop Users", "Backup Operators", "Account Operators"
}

def to_int (x, default=None):
    try:
        return int(str(x))
    except Exception:
        return default
    
def parse_evtx_ts(ts):
    if ts is None:
        return None
    if isinstance(ts, datetime):
        return ts
    s = str(ts).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    return None

def push_and_prune(dq: deque, now_dt: datetime, window: timedelta = WINDOW):
    if now_dt is None:
        return len(dq)
    cutoff = now_dt - window
    while dq and dq[0] < cutoff:
        dq.popleft()
    dq.append(now_dt)
    return len(dq)

def higher_severity(e):
    s = e.get("severity", "info")
    order = ["info", "low", "mid", "high", "CRITICAL"]
    try:
        idx = order.index(s)
        if idx < len(order)-1:
            e["severity"] = order[idx+1]
    except ValueError:
        e["severity"] = "low"

def add_severity_reason(e, reason):
    if e.get("severity_reason") in (None, "N/A"):
        e["severity_reason"] = []
    if isinstance(reason, list):
        for r in reason:
            if r not in e["severity_reason"]:
                e["severity_reason"].append(r)
    else:
        if reason not in e["severity_reason"]:
            e["severity_reason"].append(reason)
    return e

def add_mitre_id(e, mitres):
    if e.get("mitre_id") in (None, "N/A"):
        e["mitre_id"] = []
    if isinstance(mitres, list):
        for m in mitres:
            if m not in e["mitre_id"]:
                e["mitre_id"].append(m)
    else:
        if mitres not in e["mitre_id"]:
            e["mitre_id"].append(mitres)
    return e

def extract_src(ev: dict):
    ip = ev.get("IpAddress") or ev.get("SourceNetworkAddress")
    if ip and ip not in ("-", "N/A", "::1", "127.0.0.1"):
        return ip
    ws = ev.get("WorkstationName") or ev.get("ComputerName")
    return ws or "N/A"

def classify_evtx_event(ev: dict):
    if not ev:
        return suspicious_events
    
    ev.setdefault("severity", "info")
    ev.setdefault("severity_reason", "N/A")
    ev.setdefault("mitre_id", "N/A")

    eid = to_int(ev.get("EventID"))
    now_dt = parse_evtx_ts(ev.get("TimeCreated"))
    user = ev.get("TargetUserName") or ev.get("SubjectUserName") or "N/A"
    src = extract_src(ev)
    logon_type = to_int(ev.get("LogonType"))

    appended = False
    def append_once():
        nonlocal appended
        if not appended:
            suspicious_events.append(ev)
            appended = True

    if eid == 4625:
        c1 = push_and_prune(fail_by_src[src], now_dt)
        c2 = push_and_prune(fail_by_src_user[(src, user)], now_dt)

        status = (ev.get("Status") or "").lower()

        if status in ("0xc000006a", "0xc0000064", "0xc0000234"):
            add_severity_reason(ev, [f"failed logon status={status}"])

        if c2 > 3:
            higher_severity(ev)
            add_severity_reason(ev, [f"4625 burst per (src,user) 10m: {c2}"])
            add_mitre_id(ev, ["T1110"])
            append_once()

        if c1 > 6:
            higher_severity(ev)
            add_severity_reason(ev, [f"4625 burst per src 10m: {c1}"])
            add_mitre_id(ev, ["T1110"])
            append_once()

    if eid == 4624 and logon_type in (3, 10):
        pair = (src, logon_type)
        if pair not in known_sources[user]:
            known_sources[user].add(pair)
            higher_severity(ev)
            add_severity_reason(ev, [f"new source for user: {user} <- {src} (LT={logon_type})"])
            add_mitre_id(ev, ["T1078"])
            append_once()

        last_logon[user] = (now_dt, src, logon_type)

    if eid == 4672:
        prev = last_logon.get(user)
        if prev:
            last_dt, last_src, last_lt = prev
            if now_dt and last_dt and (now_dt - last_dt) <= SHORT_WINDOW:
                higher_severity(ev)
                add_severity_reason(ev, [f"4672 after 4624 within {SHORT_WINDOW.seconds//60}m (src={last_src}, LT={last_lt})"])
                add_mitre_id(ev, ["T1078"])
                append_once()

    if eid == 4720:
        higher_severity(ev)
        add_severity_reason(ev, [f"user created: {user}"])
        add_mitre_id(ev, ["T1136", "T1098"])
        append_once()

    if eid == 4726:
        higher_severity(ev)
        add_severity_reason(ev, [f"user deleted: {user}"])
        add_mitre_id(ev, ["T1098"])
        append_once()

    if eid == 4732:
        grp = ev.get("GroupName") or ev.get("TargetSid") or "N/A"
        if any(g.lower() in str(grp).lower() for g in SENSITIVE_GROUPS):
            higher_severity(ev)
            add_severity_reason(ev, [f"added to privileged group: {grp}"])
            add_mitre_id(ev, ["T1098"])
            append_once()

    if eid == 7045:
        binpath = (ev.get("ServiceFileName") or ev.get("ImagePath") or "").lower()
        higher_severity(ev)
        add_severity_reason(ev, [f"new service: {ev.get('Service Name', 'N/A')}"])
        add_mitre_id(ev, ["T1543.003"])
        if any(x in binpath for x in ("\\appdata\\", "\\temp\\", "\\users\\", "\\programdata\\")) or binpath.endswith(".exe") is False:
            higher_severity(ev)
            add_severity_reason(ev, ["suspicious service path"])
        append_once()

    if eid == 4698:
        task = ev.get("TaskName") or "N/A"
        action = (ev.get("ActionName") or ev.get("Command") or ev.get("ExecCommand") or "").lower()
        higher_severity(ev)
        add_severity_reason(ev, [f"scheduled task created: {task}"])
        add_mitre_id(ev, ["T1053.005"])
        if any(x in action for x in ("powershell", "cmd.exe", "wscript", "bitsadmin", "mshta", "rundll32")):
            higher_severity(ev)
            add_severity_reason(ev, ["suspicious task action"])
        append_once()

    if eid in (4719, 1102):
        ev["severity"] = "CRITICAL"
        if eid == 4719:
            add_severity_reason(ev, ["audit policy changed"])
        else:
            add_severity_reason(ev, ["security log cleared"])
        add_mitre_id(ev, ["T1562"])
        append_once()

    return suspicious_events