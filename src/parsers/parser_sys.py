import re

#id_rule = r'([\d]{,3}\.){3}[\d]{,3}'

#id_rule = r'([\d\d\d\.]){3}[\d\d\d]'

#id_rule = r'([0-999*]\.){3}[0-999*]'

#id_rule = r'([0-9*]\.){3}[0-9*]'

#id_rule = r'([0-9*]\.){3}[0-9\*]'

#id_rule = r'([\d*]\.){3}[\d\*]'

#id_rule = r'([\d\d\d\.]){3}[\d\d\d]'

#id_rule = r'([0-9][0-9][0-9]\.){3}[0-9][0-9][0-9]'

def parser_sys_log(line):

    user_match = r'for\s(\w){1,}\sfrom'

    password_match = r'\s(\w){1,}\spassword'

    timestamp_match = r'^(\w){3}(\s){2}(\d){1,2}\s((\d){1,2}\:){2}(\d){1,2}'

    hour_match = r'\s(\d){1,2}\:'

    ip_match = r'(\d{1,3}\.){3}\d{1,3}'

    access_match = r'server1 [a-zA-Z0-9\[\]]{2,}\:'
    

    #sshd_match = r'sshd\[(\d){4}\]'
    #port_match = r'\d{5}'
    #server_match = r'server(\d){1,}'

    #port_search = re.search(port_match, line)
    #server_search = re.search(server_match, line)
    #sshd_search = re.search(sshd_match, line)
    ip_search = re.search(ip_match, line) or "N/A"
    timestamp_search = re.search(timestamp_match, line) or "N/A"
    hour_search = re.search(hour_match, line) or "N/A"
    password_search = re.search(password_match, line) or "N/A"
    user_search = re.search(user_match, line) or "N/A"
    access_search = re.search(access_match, line) or "N/A"

    if password_search != "N/A":        
        password = password_search.group().strip()
    else:
        password = "N/A"
    if timestamp_search != "N/A":
        timestamp = timestamp_search.group().replace('  ', ' ')
    else:
        timestamp = "N/A"
    if hour_search != "N/A":
        hour = hour_search.group().strip().replace(' ', '').replace(':', '')
    else:
        hour = "N/A"
    if user_search != "N/A":
        user = user_search.group().strip().replace('for ', '').replace(' from', '')
    else:
        user = "N/A"
    if ip_search != "N/A":
        ip = ip_search.group()
    else:
        ip = "N/A"
    if access_search != "N/A":
        access = access_search.group().strip().replace('server1 ', '')
    else:
        access = "N/A"

    sys_log_parsed = {
        "severity": "info",
        "severity_reason": "N/A",
        "rule_id": "N/A",
        "password": password,
        "login_attempts": "N/A",
        "timestamp": timestamp,
        "hour": hour,
        "user": user,
        "ip": ip,
        "access": access,
        "raw": line
    }

    return sys_log_parsed


