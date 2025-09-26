import os
import json
from src.parsers.parser_sys_test import parse_sys_line
from src.rules.rules_sys_test import suspicious_events, analyze_sys_log

os.chdir(os.path.dirname(__file__))



def analyze_sys_log_test(sys_path):
    with open (sys_path, "r") as file:
        for line in file:
            sys_log_parsed = parse_sys_line(line)
            sys_log_analyzed = analyze_sys_log(sys_log_parsed)

    print(suspicious_events)
            
