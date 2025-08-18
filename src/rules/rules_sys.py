suspicious_hours = ['22', '23', '00', '01', '02', '03', '04', '05']
worth_noting_events = []
suspicious_events = []
list_of_ips = {}
def classify_sys_log(sys_log_parsed):
    if sys_log_parsed:
        for key in sys_log_parsed:

            if key == "access":
                if sys_log_parsed["access"] == "sudo:":
                    worth_noting_events.append(sys_log_parsed)

            if key == "password":
                if sys_log_parsed["password"] == "Failed password":
                    worth_noting_events.append(sys_log_parsed)

                    add_ip = sys_log_parsed["ip"]
                    if sys_log_parsed["ip"] in list_of_ips:
                        list_of_ips[add_ip] += 1
                        if list_of_ips[add_ip] > 2:
                            sys_log_parsed["severity"] = "low"
                            sys_log_parsed["severity_reason"] = "more than 2 failed login attempts"
                            sys_log_parsed["rule_id"] = "potential T1110"
                            sys_log_parsed["login_attempts"] = list_of_ips[add_ip]
                            suspicious_events.append(sys_log_parsed)

                        if list_of_ips[add_ip] > 4:
                            suspicious_events.remove(sys_log_parsed)
                            sys_log_parsed["severity"] = "mid"
                            sys_log_parsed["severity_reason"] = "more than 4 failed login attempts"
                            sys_log_parsed["rule_id"] = "potential T1110"
                            sys_log_parsed["login_attempts"] = list_of_ips[add_ip]
                            suspicious_events.append(sys_log_parsed)

                        if list_of_ips[add_ip] > 9:
                            suspicious_events.remove(sys_log_parsed)
                            sys_log_parsed["severity"] = "high"
                            sys_log_parsed["severity_reason"] = "more than 9 failed login attempts"
                            sys_log_parsed["rule_id"] = "T1110"
                            sys_log_parsed["login_attempts"] = list_of_ips[add_ip]
                            suspicious_events.append(sys_log_parsed)
                            
                    else:
                        list_of_ips[add_ip] = 1

            if key == "hour":

                if (sys_log_parsed["hour"] in suspicious_hours) and sys_log_parsed["severity"] == "high":
                    suspicious_events.remove(sys_log_parsed)
                    sys_log_parsed["severity_reason"] += " and activity within suspicious hours (22-6)"
                    suspicious_events.append(sys_log_parsed)

                if (sys_log_parsed["hour"] in suspicious_hours) and sys_log_parsed["severity"] == "mid":
                    suspicious_events.remove(sys_log_parsed)
                    sys_log_parsed["severity"] = "high"
                    sys_log_parsed["severity_reason"] += " and activity within suspicious hours (22-6)"
                    suspicious_events.append(sys_log_parsed)

                if (sys_log_parsed["hour"] in suspicious_hours) and sys_log_parsed["severity"] == "low":
                    suspicious_events.remove(sys_log_parsed)
                    sys_log_parsed["severity"] = "mid"
                    sys_log_parsed["severity_reason"] += " and activity within suspicious hours (22-6)"
                    suspicious_events.append(sys_log_parsed)

                if (sys_log_parsed["hour"] in suspicious_hours) and sys_log_parsed["severity"] == "info":
                    sys_log_parsed["severity"] = "low"
                    sys_log_parsed["severity_reason"] += " and activity within suspicious hours (22-6)"
                    suspicious_events.append(sys_log_parsed)


        return suspicious_events
    else:
        return