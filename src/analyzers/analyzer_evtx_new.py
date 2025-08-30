from src.rules.rules_evtx_new import classify_evtx_event, suspicious_events

def analyze_evtx(parsed_records_iterable):
    for ev in parsed_records_iterable:
        classify_evtx_event(ev)
    return suspicious_events