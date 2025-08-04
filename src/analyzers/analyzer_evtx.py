from Evtx.Evtx import Evtx
import xmltodict
import json
import os
from src.rules.rules_evtx import classify_evtx_log, suspicious_events
from geo_api import get_geolocation
from email_notification import send_analysis_report_evtx

os.chdir(os.path.dirname(__file__))

def analyze_evtx_log(evtx_path):
    suspicious_events.clear()
    with Evtx("../../test_logs/logon_fails_4625_evtx.evtx") as log:
        for record in log.records():
            xml = record.xml()
            data = xmltodict.parse(xml)
            classify_evtx_log(data)

def generate_report():
    send_analysis_report_evtx(suspicious_events)
    with open("../../results/suspicious_entries_evtx.json", "w") as f:
        json.dump(suspicious_events, f, indent=2)
    return suspicious_events