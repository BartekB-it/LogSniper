from Evtx.Evtx import Evtx
import xmltodict
import json
import os
from src.rules.rules_evtx import classify_evtx_log, suspicious_events

os.chdir(os.path.dirname(__file__))

with Evtx("../../test_logs/testt.evtx") as log:
    for record in log.records():
        xml = record.xml()
        data = xmltodict.parse(xml)
        print("Parsed Event:", data)
        classify_evtx_log(data)

def generate_report():
    print(json.dumps(suspicious_events, indent=2))

generate_report()