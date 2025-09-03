import re

timestamp_pattern = r"(.*?)(\:(\d){2}){2}"
host_pattern = r"\:\d+\s\w+(.*?)"
app_pattern_1 = r" \w+\["
app_pattern_2 = r"[a-zA-Z0-9]{3,}\:"
pid_pattern = r"\[\d+\]\:"
msg_pattern = r"\:\s+[a-zA-Z0-9_.+\[\]\(\)](.*?)$"

#kernel
src_pattern = r"SRC=[0-9\.]+"
dpt_pattern = r"DPT=[a-zA-Z0-9_.+]{0,}"
proto_pattern = r"PROTO=[A-Z]{0,}"
spt_pattern = r"SPT=[a-zA-Z0-9_.+]{0,}"
dst_pattern = r"DST=[0-9\.]+"

#cron
cron_user_pattern = r"\([a-zA-Z0-9_.+]+\)"
cron_cmd_pattern = r"CMD\s\([a-zA-Z0-9_.+\/]+\)"

#systemd
unit_started_pattern = r"Started"
unit_failed_pattern = r"Failed"
unit_stopping_pattern = r"Stopping"
unit_stopped_pattern = r"Stopped"
action_pattern = r"\.[a-zA-Z0-9_.+]+"

#sudo
sudo_user_pattern_1 =r"\:\s[a-zA-Z0-9]+\s\:"
sudo_user_pattern_2 = r"\:\s{2}[a-zA-Z0-9]+\s\:"
sudo_user_pattern_3 = r"\:\s{3}[a-zA-Z0-9]+\s\:"
sudo_target_pattern = r"USER=[a-zA-Z0-9_.+]+"
sudo_cmd_pattern = r"COMMAND=[a-zA-Z0-9\/]+"




def parse_sys_line(line):

    timestamp_match = re.search(timestamp_pattern, line)
    host_match = re.search(host_pattern, line)
    app_match_1 = re.search(app_pattern_1, line)
    app_match_2 = re.search(app_pattern_2, line)
    pid_match = re.search(pid_pattern, line)
    msg_match = re.search(msg_pattern, line)
    
    src_match = re.search(src_pattern, line)
    dpt_match = re.search(dpt_pattern, line)
    proto_match = re.search(proto_pattern, line)
    spt_match = re.search(spt_pattern, line)
    dst_match = re.search(dst_pattern, line)

    cron_user_match = re.search(cron_user_pattern, line)
    cron_cmd_match = re.search(cron_cmd_pattern, line)

    unit_started_match = re.search(unit_started_pattern, line)
    unit_failed_match = re.search(unit_failed_pattern, line)
    unit_stopping_match = re.search(unit_stopping_pattern, line)
    unit_stopped_match = re.search(unit_stopped_pattern, line)
    action_match = re.search(action_pattern, line)

    sudo_user_match_1 = re.search(sudo_user_pattern_1, line)
    sudo_user_match_2 = re.search(sudo_user_pattern_2, line)
    sudo_user_match_3 = re.search(sudo_user_pattern_3, line)
    sudo_target_match = re.search(sudo_target_pattern, line)
    sudo_cmd_match = re.search(sudo_cmd_pattern, line)


    timestamp = timestamp_match.group().replace("  ", " ") if timestamp_match else "N/A"
    host = host_match.group().strip(":1234567890").replace(" ", "") if host_match else "N/A"
    if app_match_1:
        app = app_match_1.group().strip(" ").replace("[", "") if app_match_1 else "N/A"
    else:
        app = app_match_2.group().strip(" ").replace(":", "") if app_match_2 else "N/A"
    pid = pid_match.group().strip("[]:") if pid_match else "N/A"
    msg = msg_match.group().replace(": ", "").replace("  ", "") if msg_match else "N/A"

    src = src_match.group().replace("SRC=", "") if src_match else "N/A"
    dpt = dpt_match.group().replace("DPT=", "") if dpt_match else "N/A"
    proto = proto_match.group().replace("PROTO=", "") if proto_match else "N/A"
    spt = spt_match.group().replace("SPT=", "") if spt_match else "N/A"
    dst = dst_match.group().replace("DST=", "") if dst_match else "N/A"

    cron_user = cron_user_match.group().strip("()") if cron_user_match else "N/A"
    cron_cmd = cron_cmd_match.group().replace("CMD (", "").replace(")", "") if cron_cmd_match else "N/A"

    unit_started = unit_started_match.group() if unit_started_match else "N/A"
    unit_failed = unit_failed_match.group() if unit_failed_match else "N/A"
    unit_stopping = unit_stopping_match.group() if unit_stopping_match else "N/A"
    unit_stopped = unit_stopped_match.group() if unit_stopped_match else "N/A"
    action = action_match.group().replace(".", "").replace("...", ".") if action_match else "N/A"
    
    if sudo_user_match_1:
        sudo_user = sudo_user_match_1.group().strip(": ") if sudo_user_match_1 else "N/A"
    elif sudo_user_match_2:
        sudo_user = sudo_user_match_2.group().strip(": ") if sudo_user_match_2 else "N/A"
    else:
        sudo_user = sudo_user_match_3.group().strip(": ") if sudo_user_match_3 else "N/A"
    sudo_target = sudo_target_match.group().replace("USER=", "") if sudo_target_match else "N/A"
    sudo_cmd = sudo_cmd_match.group().replace("COMMAND=", "").replace(" ;", "") if sudo_cmd_match else "N/A"

    kernel = {
        "src": src,
        "dpt": dpt,
        "proto": proto,
        "spt": spt,
        "dst": dst
    }

    if kernel["src"] != "N/A":

        sys_log_parsed = {
            "severity": "info",
            "severity_reason": "N/A",
            "mitre_id": "N'A",
            "timestamp": timestamp,
            "host": host,
            "app": app,
            "pid": pid,
            "msg": msg,
            "event_family": "kernel",
            "event_action": kernel,
            "raw": line
        }

        return sys_log_parsed

    cron = {
        "cron_user": cron_user,
        "cron_cmd": cron_cmd
    }

    if cron["cron_user"] != "N/A":

        sys_log_parsed = {
            "severity": "info",
            "severity_reason": "N/A",
            "mitre_id": "N'A",
            "timestamp": timestamp,
            "host": host,
            "app": app,
            "pid": pid,
            "msg": msg,
            "event_family": "cron",
            "event_action": cron,
            "raw": line
        }

        return sys_log_parsed

    systemd = {
        "unit_started": unit_started,
        "unit_failed": unit_failed,
        "unit_stopping": unit_stopping,
        "unit_stopped": unit_stopped,
        "action": action
    }

    if systemd["action"] != "N/A":

        sys_log_parsed = {
            "severity": "info",
            "severity_reason": "N/A",
            "mitre_id": "N'A",
            "timestamp": timestamp,
            "host": host,
            "app": app,
            "pid": pid,
            "msg": msg,
            "event_family": "systemd",
            "event_action": systemd,
            "raw": line
        }

        return sys_log_parsed

    sudo = {
        "sudo_user": sudo_user,
        "sudo_target": sudo_target,
        "sudo_cmd": sudo_cmd
    }

    if sudo["sudo_user"] != "N/A":

        sys_log_parsed = {
            "severity": "info",
            "severity_reason": "N/A",
            "mitre_id": "N/A",
            "timestamp": timestamp,
            "host": host,
            "app": app,
            "pid": pid,
            "msg": msg,
            "event_family": "sudo",
            "event_action": sudo,
            "raw": line
        }

        return sys_log_parsed
    
    else:
        sys_log_parsed = {
            "severity": "info",
            "severity_reason": "N/A",
            "mitre_id": "N/A",
            "timestamp": timestamp,
            "host": host,
            "app": app,
            "pid": pid,
            "msg": msg,
            "event_family": "other",
            "event_action": "N/A",
            "raw": line
        }