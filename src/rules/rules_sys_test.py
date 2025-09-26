# src/rules/rules_sys_test.py
from collections import deque, defaultdict
from datetime import datetime, timedelta
import re

suspicious_events = []

WINDOW = timedelta(minutes=10)
SHORT_WINDOW = timedelta(minutes=2)

# kernel
ufw_window_by_src = defaultdict(deque)
unique_dpt_by_src = defaultdict(deque)
sensitive_port_hits = defaultdict(deque)
external_src_last_noted = {}

SENSITIVE_PORTS = {"22", "23", "139", "445", "3389", "5900", "3306"}

# cron
known_cron_users = set()
cron_burst = defaultdict(deque)
CRON_SUS_WORDS = (
    "curl", "wget", "python", "perl", "bash -c", "sh -c", "nc", "socat",
    "chattr", "chmod +s", "base64", "openssl", "scp", "ftp", "tftp"
)
CRON_SUS_PATH_HINTS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/.", "/.config/")

# systemd
systemd_window_by_unit = defaultdict(deque)
systemd_fail = defaultdict(deque)
systemd_transitions = defaultdict(deque)
_seen_units = set()  # first-seen units per host

# sudo
sudo_window_by_user = defaultdict(deque)
sudo_unique_cmd_by_user = defaultdict(deque)
known_sudo_users = set()

SHELL_LIKE = ("bash", "sh", "zsh", "ksh", "python", "perl", "ruby")
SENSITIVE_SUDO_CMDS = (
    "useradd", "adduser", "usermod", "passwd", "chage", "visudo",
    "systemctl", "service",
    "chmod", "chown", "chattr", "setcap", "setfacl",
    "mount", "umount",
    "tcpdump", "nmap", "socat", "nc", "ncat", "netcat",  # <- nmap (fix)
    "curl", "wget", "scp", "ssh"
)

def higher_severity(e):
    if e["severity"] == "CRITICAL":
        return
    elif e["severity"] == "high":
        e["severity"] = "CRITICAL"; return
    elif e["severity"] == "mid":
        e["severity"] = "high"; return
    elif e["severity"] == "low":
        e["severity"] = "mid"; return
    else:
        e["severity"] = "low"; return

def add_severity_reason(e, reason):
    if e["severity_reason"] == "N/A":
        e["severity_reason"] = []
    for r in (reason if isinstance(reason, list) else [reason]):
        if r not in e["severity_reason"]:
            e["severity_reason"].append(r)

def add_mitre(e, mitres):
    if e["mitre_id"] == "N/A":
        e["mitre_id"] = []
    for m in (mitres if isinstance(mitres, list) else [mitres]):
        if m not in e["mitre_id"]:
            e["mitre_id"].append(m)

def parse_syslog_dt(dt):
    year = datetime.now().year
    return datetime.strptime(f"{year} {dt}", "%Y %b %d %H:%M:%S")

def push_and_prune(dq: deque, now_dt: datetime, window: timedelta = WINDOW):
    if now_dt is None:
        return len(dq)
    cutoff = now_dt - window
    while dq and dq[0] < cutoff:
        dq.popleft()
    dq.append(now_dt)
    return len(dq)

def push_prune_and_count_unique(dq: deque, now_dt: datetime, value: str, window: timedelta = WINDOW):
    if now_dt is None:
        return 0
    cutoff = now_dt - window
    while dq and dq[0][0] < cutoff:
        dq.popleft()
    dq.append((now_dt, value))
    return len({v for _, v in dq})

def only_prune(dq: deque, now_dt: datetime, window: timedelta = WINDOW):
    if now_dt is None:
        return len(dq)
    cutoff = now_dt - window
    while dq and dq[0] < cutoff:
        dq.popleft()
    return len(dq)

_UNIT_RE = re.compile(r"([A-Za-z0-9_.@-]+\.service)\b")
def extract_unit_from_msg(msg: str) -> str | None:
    if not msg or msg == "N/A":
        return None
    m = _UNIT_RE.search(msg)
    return m.group(1) if m else None

def parse_sudo_user_from_msg(msg: str) -> str | None:
    if not msg:
        return None
    m = re.search(r"\s([A-Za-z0-9._-]+)\s:\sTTY=", msg)
    return m.group(1) if m else None

def parse_sudo_cmd_from_msg(msg: str) -> str | None:
    if not msg:
        return None
    m = re.search(r"COMMAND=([^\s;][^\n]*)", msg)
    return m.group(1).strip() if m else None

def is_noninteractive_tty(msg: str) -> bool:
    m = msg or ""
    return ("TTY=unknown" in m) or ("TTY=?" in m)

def parse_user_from_sudo_failure(msg: str) -> str:
    if not msg:
        return "N/A"
    m = re.search(r"user=([A-Za-z0-9._-]+)", msg)
    return m.group(1) if m else "N/A"

def analyze_sys_log(e):
    ef = e.get("event_family")
    ea = e.get("event_action", {}) or {}

    # UŻYWAJ teraz w KAŻDEJ gałęzi:
    now_dt = parse_syslog_dt(e.get("timestamp", "Jan  1 00:00:00"))

    line_appended = False
    def append_once(ev):
        nonlocal line_appended
        if not line_appended:
            suspicious_events.append(ev)
            line_appended = True

    # -------- kernel --------
    if ef == "kernel":
        src = ea.get("src")
        dpt = ea.get("dpt")
        proto = ea.get("proto")

        has_all = all(v and v != "N/A" for v in (src, dpt, proto))
        if has_all:
            count_burst = push_and_prune(ufw_window_by_src[src], now_dt)

            if count_burst > 10:
                higher_severity(e)
                add_severity_reason(e, [f"UFW burst per SRC (10m): {count_burst}"])
                add_mitre(e, ["T1595.002"])
                append_once(e)
            if count_burst > 25:
                higher_severity(e)
                add_severity_reason(e, ["heavy UFW burst per SRC (10m)"])
                append_once(e)

            uniq_ports = push_prune_and_count_unique(unique_dpt_by_src[src], now_dt, dpt)
            if uniq_ports > 7:
                higher_severity(e)
                add_severity_reason(e, [f"port-scan: {uniq_ports} unique DPT (10m)"])
                add_mitre(e, ["T1595.002"])
                append_once(e)

            if str(dpt) in SENSITIVE_PORTS:
                hits = push_and_prune(sensitive_port_hits[(src, str(dpt))], now_dt)
                if hits > 5:
                    higher_severity(e)
                    add_severity_reason(e, [f"repeated hits on sensitive port {dpt} (10m): {hits}"])
                    add_mitre(e, ["T1595.001"])
                    append_once(e)
                if hits > 15:
                    higher_severity(e)
                    add_severity_reason(e, ["heavy focus on sensitive port"])
                    append_once(e)

            if src and not (str(src).startswith("10.") or str(src).startswith("192.168.") or str(src).startswith("172.16.")):
                last = external_src_last_noted.get(src)
                if (last is None) or (now_dt and (now_dt - last) >= WINDOW):
                    add_severity_reason(e, [f"external source ({src})"])
                    external_src_last_noted[src] = now_dt
                    append_once(e)

            if count_burst > 10 and uniq_ports > 7:
                higher_severity(e)
                add_severity_reason(e, ["combined: burst + unique DPT"])
                append_once(e)

    # -------- cron --------
    if ef == "cron":
        user = ea.get("cron_user") or "N/A"
        cmd = (ea.get("cron_cmd") or "").strip()

        if user != "N/A":
            lower_cmd = cmd.lower()
            sus = any(k in lower_cmd for k in CRON_SUS_WORDS) or any(h in lower_cmd for h in CRON_SUS_PATH_HINTS)
            if sus:
                higher_severity(e)
                add_severity_reason(e, [f"suspicious cron cmd: {cmd}"])
                if any(x in lower_cmd for x in ("curl", "wget", "scp", "ftp", "tftp", "http://", "https://")):
                    add_mitre(e, ["T1053.003", "T1105"])
                else:
                    add_mitre(e, ["T1053.003"])
                append_once(e)

            # <- TU był błąd w f-stringu (cudzysłowy)
            key_user = f"{e.get('host', '')}/{user}"
            if key_user not in known_cron_users:
                known_cron_users.add(key_user)
                add_severity_reason(e, [f"new cron user: {user}"])
                add_mitre(e, ["T1053.003"])
                append_once(e)

            if cmd:
                n = push_and_prune(cron_burst[(user, cmd)], now_dt)
                if n > 5:
                    higher_severity(e)
                    add_severity_reason(e, [f"cron burst (user={user}, 10m): {n}"])
                    add_mitre(e, ["T1053.003"])
                    append_once(e)
                if n > 15:
                    higher_severity(e)
                    add_severity_reason(e, ["heavy cron burst (10m)"])
                    append_once(e)

    # -------- systemd --------
    if ef == "systemd":
        unit = ea.get("unit")
        if not unit or unit == "N/A":
            unit = extract_unit_from_msg(e.get("msg", "")) or "N/A"
        unit_norm = unit.lower() if unit != "N/A" else "N/A"

        failed_flag = ((ea.get("unit_failed") or "").lower() == "failed")
        started_flag = ((ea.get("unit_started") or "").lower() == "started")
        stopped_flag = ((ea.get("unit_stopped") or "").lower() == "stopped")

        if failed_flag:
            f = push_and_prune(systemd_fail[unit_norm], now_dt)
            if f >= 1:
                higher_severity(e)
                add_severity_reason(e, [f"systemd failed: {unit_norm}"])
                add_mitre(e, ["T1569.002"])
                append_once(e)
            if f >= 3:
                higher_severity(e)
                add_severity_reason(e, [f"systemd unit failing repeatedly (10m): {f}"])
                append_once(e)

        if unit_norm != "N/A":
            c_sys = push_and_prune(systemd_window_by_unit[unit_norm], now_dt, window=SHORT_WINDOW)
            if c_sys > 3:
                higher_severity(e)
                add_severity_reason(e, [f"systemd flapping: {unit_norm} ({SHORT_WINDOW.seconds//60}m) count={c_sys}"])
                add_mitre(e, ["T1569.002", "T1543.002"])
                append_once(e)

        if started_flag and unit_norm != "N/A":
            host = e.get("host", "")
            key = f"{host}/{unit_norm}"
            if key not in _seen_units:
                _seen_units.add(key)
                higher_severity(e)
                add_severity_reason(e, [f"new systemd unit: {unit_norm}"])
                add_mitre(e, ["T1543.002"])
                append_once(e)

            msg_low = (e.get("msg", "") or "").lower()
            if any(x in msg_low for x in ("/tmp/", "/var/tmp/", "/dev/shm/")) or unit_norm.startswith(("tmp@", "home-")):
                higher_severity(e)
                add_severity_reason(e, ["suspicious unit name/path"])
                append_once(e)

        if (started_flag or stopped_flag) and unit_norm != "N/A":
            tr = push_and_prune(systemd_transitions[unit_norm], now_dt)
            if tr >= 8:
                higher_severity(e)
                add_severity_reason(e, [f"systemd start/stop: {unit_norm} (10m): {tr}"])
                add_mitre(e, ["T1543.002"])  # <- fix z T543.002
                append_once(e)

    # -------- sudo --------
    if ef == "sudo":
        user = (ea.get("sudo_user") or parse_sudo_user_from_msg(e.get("msg", "")) or "").strip()
        target = (ea.get("sudo_target") or "").strip()
        cmd_full = (ea.get("sudo_cmd") or parse_sudo_cmd_from_msg(e.get("msg", "")) or "").strip()

        # <- TU był rozbity string / cudzysłowy
        cmd_base = cmd_full.split("/")[-1].split()[0].lower() if cmd_full else ""

        if user and cmd_base:
            if user not in known_sudo_users:
                known_sudo_users.add(user)
                higher_severity(e)
                add_severity_reason(e, [f"first sudo usage for user: {user}"])
                add_mitre(e, ["T1548.003"])
                append_once(e)

            cnt = push_and_prune(sudo_window_by_user[user], now_dt)
            if cnt > 3:
                higher_severity(e)
                add_severity_reason(e, [f"sudo burst per user (10m): {cnt}"])
                add_mitre(e, ["T1548.003"])
                append_once(e)
            if cnt > 7:
                higher_severity(e)
                add_severity_reason(e, ["heavy sudo burst per user (10m)"])
                append_once(e)

            uniq = push_prune_and_count_unique(sudo_unique_cmd_by_user[user], now_dt, cmd_base)
            if uniq > 5:
                higher_severity(e)
                add_severity_reason(e, [f"multiple unique sudo commands (10m): {uniq}"])
                add_mitre(e, ["T1548.003"])
                append_once(e)

            if cmd_base in SENSITIVE_SUDO_CMDS:
                higher_severity(e)
                add_severity_reason(e, [f"sudo sensitive command: {cmd_base}"])
                add_mitre(e, ["T1548.003"])
                append_once(e)

            if cmd_base in SHELL_LIKE:
                higher_severity(e)
                add_severity_reason(e, [f"sudo shell/Interpreter: {cmd_base}"])
                add_mitre(e, ["T1059"])
                append_once(e)

            if cnt > 3 and (cmd_base in SENSITIVE_SUDO_CMDS or cmd_base in SHELL_LIKE):
                higher_severity(e)
                add_severity_reason(e, ["combined: sudo burst + sensitive/shell command"])
                append_once(e)

        msg = e.get("msg", "") or ""
        if "authentication failure" in msg.lower():
            u = parse_user_from_sudo_failure(msg) or user or "N/A"
            if u != "N/A":
                f = push_and_prune(sudo_window_by_user[u], now_dt)
                if f > 2:
                    higher_severity(e)
                    add_severity_reason(e, [f"sudo failures (10m) for user={u}: {f}"])
                    add_mitre(e, ["T1110"])
                    append_once(e)
                if f > 5:
                    higher_severity(e)
                    add_severity_reason(e, ["severe sudo failure burst"])
                    append_once(e)

    return e
