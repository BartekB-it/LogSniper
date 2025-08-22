suspicious_events = []
list_of_ips = {}

def classify_access_log(access_log_parsed):

    def higher_severity(access_log_parsed):

        if access_log_parsed["severity"] == "high":
            return access_log_parsed

        if access_log_parsed["severity"] == "mid":
            access_log_parsed["severity"] = "high"
            return access_log_parsed

        if access_log_parsed["severity"] == "low":
            access_log_parsed["severity"] = "mid"
            return access_log_parsed

        if access_log_parsed["severity"] == "info":
            access_log_parsed["severity"] = "low"
            return access_log_parsed
        
    def add_severity_reason(access_log_parsed, severity_reason):
        if access_log_parsed["severity_reason"] == "N/A":
            access_log_parsed["severity_reason"] = severity_reason
            return access_log_parsed
        elif "attempts".find(access_log_parsed["severity_reason"]) > 0 :
            access_log_parsed["severity_reason"] = severity_reason
            return access_log_parsed
        else:
            access_log_parsed["severity_reason"] += " & "
            access_log_parsed["severity_reason"] += severity_reason
            return access_log_parsed

    def add_mitre_id(access_log_parsed, mitre_id):
        if access_log_parsed["mitre_id"] == "N/A":
            access_log_parsed["mitre_id"] = mitre_id
            return access_log_parsed
        else:
            access_log_parsed["mitre_id"] += mitre_id
            return access_log_parsed

    if access_log_parsed:
        for key in access_log_parsed:
            if key == "status": #HTTP error burst - fuzzing / directory bruteforce
                if access_log_parsed["status"] == "404" or access_log_parsed["status"] == "401" or access_log_parsed["status"] == "403":
                    if access_log_parsed["ip"] in list_of_ips:
                        list_of_ips[access_log_parsed["ip"]] += 1
                        if list_of_ips[access_log_parsed["ip"]] > 2:
                            higher_severity(access_log_parsed)
                            reason = "more than 2 failed login attempts"
                            add_severity_reason(access_log_parsed, reason)
                            access_log_parsed["404/401/403_attempts"] = list_of_ips[access_log_parsed["ip"]]
                            mitre_id = ["T1595.002", "T1190"]
                            add_mitre_id(access_log_parsed, mitre_id)
                            suspicious_events.append(access_log_parsed)

                        if list_of_ips[access_log_parsed["ip"]] > 4:
                            suspicious_events.remove(access_log_parsed)
                            higher_severity(access_log_parsed)
                            reason = "more than 4 failed login attempts"
                            add_severity_reason(access_log_parsed, reason)
                            access_log_parsed["404/401/403_attempts"] = list_of_ips[access_log_parsed["ip"]]
                            suspicious_events.append(access_log_parsed)

                        if list_of_ips[access_log_parsed["ip"]] > 9:
                            suspicious_events.remove(access_log_parsed)
                            higher_severity(access_log_parsed)
                            reason = "more than 9 failed login attempts"
                            add_severity_reason(access_log_parsed, reason)
                            access_log_parsed["404/401/403_attempts"] = list_of_ips[access_log_parsed["ip"]]
                            suspicious_events.append(access_log_parsed)
                    else:
                        list_of_ips[access_log_parsed["ip"]] = 1

                    if list_of_ips[access_log_parsed["ip"]] > 99: #High request rate per IP -> could be DDoS / fuzzing
                        higher_severity(access_log_parsed)
                        reason = "high request rate per IP (potential DDoS / fuzzing)"
                        add_severity_reason(access_log_parsed, reason)
                        mitre_id = ["T1595", "T1498.001"]
                        add_mitre_id(access_log_parsed, mitre_id)
                        suspicious_events.append(access_log_parsed)

            if key == "path": #suspicious URls -> higher severity
                suspicious_URls = ["phpmyadmin", "/etc/passwd", "/wp-login.php", "/admin", "/env", "/wp-admin", "/server-status", "/.git", "/config.php"]
                if any(url in access_log_parsed["path"] for url in suspicious_URls):
                    higher_severity(access_log_parsed)
                    reason = "suspicious URl"
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1190"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    suspicious_events.append(access_log_parsed)

            if key == "path": #SQLi patterns
                SQL_injection = ["' OR 1=1 --", "' OR '1'='1", "union select", "UNION SELECT", "information_schema", "--", "/*", "%27", "%3B"]
                if any(inj in access_log_parsed["path"] for inj in SQL_injection):
                    higher_severity(access_log_parsed)
                    reason = "SQLi pattern"
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1190"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    suspicious_events.append(access_log_parsed)

            if key == "path": #command injection patterns
                command_injection = [";wget", ";curl", "|bash", "&&", "`cmd`", "$()"]
                if any(inj in access_log_parsed["path"] for inj in command_injection):
                    higher_severity(access_log_parsed)
                    reason = "command injection pattern"
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1059"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    suspicious_events.append(access_log_parsed)

            if key == "user_agent": #anomalous User-Agent
                anomalous_ua = ["curl", "python-requests", "sqlmap", "nikto"]
                if any(ua in access_log_parsed["user_agent"] for ua in anomalous_ua):
                    higher_severity(access_log_parsed)
                    reason = "anomalous user-agent (potential scanner)"
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1595", "T1036.005"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    suspicious_events.append(access_log_parsed)

            if key == "method": #strange method
                strange_method = ["DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]
                if any(method in access_log_parsed["method"] for method in strange_method):
                    higher_severity(access_log_parsed)
                    reason = "strange method"
                    add_severity_reason(access_log_parsed, reason)
                    mitre_id = ["T1071.001", "T1190"]
                    add_mitre_id(access_log_parsed, mitre_id)
                    suspicious_events.append(access_log_parsed)
#        if access_log_parsed["mitre_id"] != "N/A":
#            for i in access_log_parsed["mitre_id"]:
#                print(type(access_log_parsed["mitre_id"]))
#                if access_log_parsed["mitre_id"][i] == access_log_parsed["mitre_id"][i + 1]:
#                    access_log_parsed["mitre_id"].remove(access_log_parsed["mitre_id"][i])
#                else:
#                    continue

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