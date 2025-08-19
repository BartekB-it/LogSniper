suspicious_events = []
list_of_ips = {}

def classify_auth_log(auth_log_parsed):
    if auth_log_parsed:
        for key in auth_log_parsed:
            print(key)
            if key == "password":
                if auth_log_parsed["password"] == "Failed password":

                    add_ip = auth_log_parsed["ip"]

                    if auth_log_parsed["ip"] in list_of_ips:
                        list_of_ips[add_ip] += 1
                        if list_of_ips[add_ip] > 2:
                            auth_log_parsed["login_attempts"] = list_of_ips[add_ip]
                            suspicious_events.append(auth_log_parsed)
                    else:
                        list_of_ips[add_ip] = 1
        return suspicious_events
    else:
        return
