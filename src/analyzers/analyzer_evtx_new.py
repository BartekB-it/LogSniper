from pathlib import Path
from src.rules.rules_evtx_new import classify_evtx_event, suspicious_events
import xmltodict

def _iter_evtx_records(evtx_path):
    try:
        from Evtx.Evtx import Evtx
    except ImportError as e:
        raise RuntimeError(
            "No 'python-evtx' module. Install: pip install python-evtx xmltodict"
            ) from e
    
    with Evtx(str(evtx_path)) as log:
        for rec in log.records():
            xml = rec.xml()
            try:
                d = xmltodict.parse(xml)
            except Exception:
                continue

            evt = d.get("Event", {})
            sys = evt.get("System", {})
            ed = evt.get("EventData", {})
            ud = evt.get("UserData", {})

            out = {}

            eid = sys.get("EventID")
            if isinstance(eid, dict):
                eid = eid.get("#text") or eid.get("Qualifiers") or None
            out["EventID"] = eid

            tc = sys.get("TimeCreated", {})
            out["TimeCreated"] = tc.get("@SystemTime") if isinstance(tc, dict) else tc
            out["ComputerName"] = sys.get("Computer")

            def fold(container):
                res = {}
                if not isinstance(container, dict):
                    return res
                data = container.get("Data")
                if data is None:
                    return res
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            name = item.get("@Name")
                            val = item.get("#text")
                            if name:
                                res[name] = val
                elif isinstance(data, dict):
                    name = data.get("@Name")
                    val = data.get("#text")
                    if name:
                        res[name] = val
                return res
            
            out.update(fold(ed))
            out.update(fold(ud))

            yield out

def analyze_evtx(evtx_input):

    if isinstance(evtx_input, (str, Path)):
        for ev in _iter_evtx_records(evtx_input):
            classify_evtx_event(ev)
            print(ev)

    else:
        for ev in evtx_input:
            classify_evtx_event(ev)
    return suspicious_events