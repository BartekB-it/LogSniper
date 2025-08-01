from Evtx.Evtx import Evtx
import xmltodict
import json
import os
from src.rules.rules_evtx import classify_evtx_log, suspicious_events

os.chdir(os.path.dirname(__file__))

with Evtx("../../test_logs/logon_fails_4625_evtx.evtx") as log:
    for record in log.records():
        xml = record.xml()
        data = xmltodict.parse(xml)
        classify_evtx_log(data)

def generate_report():
    return suspicious_events