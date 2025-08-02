from collections import defaultdict

ip_404_counter = defaultdict(int)
#url_ip_map = defaultdict(set)

def classify_access_log(log_entry):
    ua = log_entry["user_agent"].lower()
    ip = log_entry["ip"]
    path = log_entry["path"].lower()
    method = log_entry["method"]
    status = log_entry["status"]

    if "sqlmap" in ua:
        return "SQLMAP_SCANNER"
    elif "nikto" in ua:
        return "NIKTO_SCANNER"
    elif "curl" in ua:
        return "CURL_SCANNER"
    elif "urllib" in ua and "PATCH" in method:
        return "POTENTIAL_API_MANIPULATION"
    elif "OPTIONS" in method or "HEAD" in method or "DELETE" in method:
        return "STRANGE_METHOD"
    elif "setup.cgi" in path:
        return "POTENTIAL_SETUP_CGI_SCANNER"
    elif "config.php" in path:
        return "POTENTIAL_CONFIG_PHP_SCANNER"
    elif "hidden" in path:
        return "POTENTIAL_SUSPICIOUS_PATH_SCANNER"
    elif status == "403" and path == "/login":
        return "POTENTIAL_BRUTEFORCE"
    elif ip_404_counter[ip] > 20:
        return "POTENTIAL_404_FLOOD"
#    elif len(url_ip_map[path]) > 10:
#        return "POTENTIAL_SCAN"
    else:
        return "NORMAL"