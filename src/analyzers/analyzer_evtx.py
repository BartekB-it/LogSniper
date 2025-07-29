from Evtx.Evtx import Evtx
import xmltodict
import json
import os

os.chdir(os.path.dirname(__file__))

with Evtx("../../test_logs/ID4625-failed login with denied access due to account restriction.evtx") as log:
    for record in log.records():
        xml = record.xml()
        data = xmltodict.parse(xml)
        print (json.dumps(data, indent=2))