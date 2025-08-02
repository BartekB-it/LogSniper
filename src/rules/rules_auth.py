from collections import defaultdict

failed_attempts = defaultdict(int)
BRUTE_FORCE_THRESHOLD = 10

def classify_auth_log(line):
    if "Failed password" in line:
        return "FAILED_LOGIN"
    elif "Accepted password" in line:
        return "SUCCESSFUL_LOGIN"
    elif "sudo" in line:
        return "SUDO_USAGE"
    else:
        return "UNKNOWN"