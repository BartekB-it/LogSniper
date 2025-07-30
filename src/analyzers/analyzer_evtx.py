from Evtx.Evtx import Evtx
import xmltodict
import json
import os
from src.rules.rules_evtx import classify_evtx_log, suspicious_events

os.chdir(os.path.dirname(__file__))

with Evtx("../../test_logs/CA_4624_4625_LogonType2_LogonProc_chrome.evtx") as log:
    for record in log.records():
        xml = record.xml()
        data = xmltodict.parse(xml)
        classify_evtx_log(data)

def generate_report():
    print(json.dumps(suspicious_events, indent=2))

generate_report()