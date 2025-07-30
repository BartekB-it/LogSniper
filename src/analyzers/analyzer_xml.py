import xmltodict
import json
import os
from src.rules.rules_xml import classify_xml_log, suspicious_events_xml

os.chdir(os.path.dirname(__file__))

def generate_report_xml():
    with open("../../test_logs/test_bruteforce_final.xml", "r", encoding="utf-8") as f:
        xml_content = f.read()
        data = xmltodict.parse(xml_content)

        print(json.dumps(data, indent=2))
        exit()

#        if isinstance(data["Events"]["Event"], list):
 #           for event in data["Events"]["Event"]:
 #               classify_xml_log({"Event": event})
 #       else:
 #           classify_xml_log({"Event": data["Events"]["Event"]})

  #  print(json.dumps(suspicious_events_xml, indent=2))