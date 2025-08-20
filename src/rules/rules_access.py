
#url_ip_map = defaultdict(set)

suspicious_events = []
list_of_ips = {}

def classify_access_log(access_log_parsed):

   

    if access_log_parsed:
        for key in access_log_parsed:
            if key == "status": #HTTP error burst - fuzzing / directory bruteforce
                if access_log_parsed["status"] == "404" or access_log_parsed["status"] == "401" or access_log_parsed["status"] == "403":

                    add_ip = access_log_parsed["ip"]

                    if access_log_parsed["ip"] in list_of_ips:
                        list_of_ips[add_ip] += 1
                        if list_of_ips[add_ip] > 2:
                            access_log_parsed["404/401/403_attempts"] = list_of_ips[add_ip]
                            suspicious_events.append(access_log_parsed)
                    else:
                        list_of_ips[add_ip] = 1
                    if list_of_ips[add_ip] > 99: #High request rate per IP -> could be DDoS / fuzzing
                        suspicious_events.append(access_log_parsed)
            if key == "path": #suspicious URls -> higher severity
                if ("phpmyadmin" or "/etc/passwd" or "/wp-login.php" or "/admin") in access_log_parsed["path"]:
                    suspicious_events.append(access_log_parsed)
            if key == "path": #SQLi / command injection patterns
                if ("' OR 1=1 --" or ";wget" or "union select") in access_log_parsed["path"]:
                    suspicious_events.append(access_log_parsed)
            if key == "user_agent": #anomalous User-Agent
                if ("curl" or "python-requests" or "sqlmap" or "nikto") in access_log_parsed["user_agent"]:
                    suspicious_events.append(access_log_parsed)
        return suspicious_events
    else:
        return





#    ua = log_entry["user_agent"].lower()
#    ip = log_entry["ip"]
#    path = log_entry["path"].lower()
#    method = log_entry["method"]
#    status = log_entry["status"]



#    if "sqlmap" in ua:
#        return "SQLMAP_SCANNER"
#    elif "nikto" in ua:
#        return "NIKTO_SCANNER"
#    elif "curl" in ua:
#        return "CURL_SCANNER"
#    elif "urllib" in ua and "PATCH" in method:
#        return "POTENTIAL_API_MANIPULATION"
#    elif "OPTIONS" in method or "HEAD" in method or "DELETE" in method:
#        return "STRANGE_METHOD"
#    elif "setup.cgi" in path:
#       return "POTENTIAL_SETUP_CGI_SCANNER"
#   elif "config.php" in path:
#        return "POTENTIAL_CONFIG_PHP_SCANNER"
#    elif "hidden" in path:
#        return "POTENTIAL_SUSPICIOUS_PATH_SCANNER"
#    elif status == "403" and path == "/login":
#        return "POTENTIAL_BRUTEFORCE"
#    elif ip_404_counter[ip] > 20:
#        return "POTENTIAL_404_FLOOD"
#    elif len(url_ip_map[path]) > 10:
#        return "POTENTIAL_SCAN"
#    else:
#        return "NORMAL"