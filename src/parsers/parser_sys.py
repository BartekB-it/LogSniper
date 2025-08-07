import os
import re

for_who_match = r'for\s(\w){1,}\sfrom'

password_match = r'\s(\w){1,}\spassword'

sshd_match = r'sshd\[(\d){4}\]'

server_match = r'server(\d){1,}'

timestamp_match = r'^(\w){3}(\s){2}(\d){1,2}\s((\d){1,2}\:){2}(\d){1,2}'

port_match = r'\d{5}'

id_match = r'(\d{1,3}\.){3}\d{1,3}'

#id_rule = r'([\d]{,3}\.){3}[\d]{,3}'

#id_rule = r'([\d\d\d\.]){3}[\d\d\d]'

#id_rule = r'([0-999*]\.){3}[0-999*]'

#id_rule = r'([0-9*]\.){3}[0-9*]'

#id_rule = r'([0-9*]\.){3}[0-9\*]'

#id_rule = r'([\d*]\.){3}[\d\*]'

#id_rule = r'([\d\d\d\.]){3}[\d\d\d]'

#id_rule = r'([0-9][0-9][0-9]\.){3}[0-9][0-9][0-9]'

suspicious_events = []

with open("c:/Users/Admin/LogSniper-fresh/test_logs/syslog.log", "r") as file:
    for line in file:
        id_search = re.search(id_match, line)
        port_search = re.search(port_match, line)
        timestamp_search = re.search(timestamp_match, line)
        server_search = re.search(server_match, line)
        sshd_search = re.search(sshd_match, line)
        password_search = re.search(password_match, line)
        for_who_search = re.search(for_who_match, line)
        if id_search and port_search and password_search and for_who_search:
            print(id_search.group(), port_search.group(), timestamp_search.group(), server_search.group(), sshd_search.group(), password_search.group(), for_who_search.group())
            if password_search.group().strip() == "Failed password":
                suspicious_events.append(line)
        
print(suspicious_events)


