import os
import json
import xmltodict
from Evtx.Evtx import Evtx
from src.analyzers.analyzer_access import analyze_access_log
from src.analyzers.analyzer_auth import analyze_auth_log
from src.analyzers.analyzer_evtx import generate_report
from src.rules.rules_evtx import classify_evtx_log, suspicious_events

os.chdir(os.path.dirname(__file__))

TEST_LOGS_DIR = "test_logs"
RESULTS_DIR = "results"

os.makedirs(RESULTS_DIR, exist_ok=True)

def main():
    for filename in os.listdir(TEST_LOGS_DIR):
        if filename.endswith(".csv"):
            continue
        
        log_path = os.path.join(TEST_LOGS_DIR, filename)

        print(f"\n Analyzing: {filename}")

        if "access" in filename or "apache" in filename:
            results = analyze_access_log(log_path)
        elif "auth" in filename:
            results = analyze_auth_log(log_path)
        elif "evtx" in filename:
            suspicious_events.clear()
            with Evtx(log_path) as log:
                for record in log.records():
                    xml = record.xml()
                    data = xmltodict.parse(xml)
                    classify_evtx_log(data)
                    
            results = generate_report()
            print(f"EVTX results: {json.dumps(results, indent=2)}")
        else:
            print(f"Skipped {filename}: unknown type")
            continue
        
        if filename.endswith(".log"):
            output_filename = filename.replace(".log", ".json")
        elif filename.endswith(".evtx"):
            output_filename = filename.replace(".evtx", ".json")
        output_path = os.path.join(RESULTS_DIR, output_filename)

        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)

        print(f"Saved results to {output_path} ({len(results)} entries)")

if __name__ == "__main__":
    main()