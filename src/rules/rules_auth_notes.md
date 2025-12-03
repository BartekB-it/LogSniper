AUTH_BRUTE_FORCE_1
- What it detects: detects 3 or more failed SSH logins from the same source IP to the same user within 10 minutes window
- Severity: +1
- Fields: password, list_of_ips
- Additional fields:
    - mitre_id = ["T1110"]
    - reason = ["more than 2 failed login attempts (10m window)"]

AUTH_BRUTE_FORCE_2
- What it detects: detects 5 or more failed SSH logins from the same source IP to the same user within 10 minutes window
- Severity: +1
- Fields: password, list_of_ips
- Additional fields:
    - reason = ["more than 4 failed login attempts (10m window)"]

AUTH_BRUTE_FORCE_3
- What it detects: detects 10 or more failed SSH logins from the same source IP to the same user within 10 minutes window
- Severity: +1
- Fields:  password, list_of_ips
- Additional fields:
    - reason = ["more than 9 failed login attempts (10m window)"]

AUTH_HIGH_REQ_RATE_1
- What it detects: detects 100 or more auth tries per IP within 10 minutes window
- Severity: +1
- Fields: password, req_count_10m
- Additional fields:
    - mitre_id = ["T1595", "T1489.001"]
    - reason = ["high connection/auth rate per IP (10m window): {req_count_10m}"]

AUTH_TARGETED_BRUTE_FORCE_1
- What it detects: detects 5 or more targeted brute force attempts for one specific user within 10 minutes window
- Severity: +1
- Fields: password, user_key, user_fails_10m
- Additional fields:
    - mitre_id = ["T1110"]
    - reason = ["targeted user brute attempts (10m window)"]

AUTH_SUCCESSFUL_BRUTE_FORCE_1
- What it detects: detects successful login after 5 or more brute force attempts within 10 minutes window
- Severity: if already CRITICAL - stays CRITICAL; otherwise - automatically high
- Fields: password, list_of_ips
- Additional fields:
    - mitre_id = ["T1110", "T1078"]
    - reason = ["accepted password after brute force (warning!)"]

AUTH_INVALID_USER_1
- What it detects: detects invalid user attempt
- Severity: +1
- Fields: user
- Additional fields:
    - mitre_id = ["1087.001"]
    - reason = ["invalid user"]

AUTH_INVALID_USER_BURST_1
- What it detects: detects 5 or more invalid user attmepts within 10 minutes window
- Severity: +1
- Fields: user, invalid_user_attempts
- Additional fields:
    - reason = ["invalid user burst (10m window)"]

AUTH_ROOT_LOGIN_ATTEMPT_1
- What it detects: detects failed root login attempt
- Severity: unchanged
- Fields: user, password
- Additional fields:
    - reason = ["root login attempt"]

AUTH_ROOT_LOGIN_SUCCESSFUL_1
- What it detects: detects successful root login
- Severity: unchanged
- Fields: user, password
- Additional fields:
    - mitre_id = ["T1078"]
    - reason = ["root login success"]

AUTH_ROOT_BRUTE_FORCE_1
- What it detects: detects 3 or more root login attempts within 10 minutes window
- Severity: +1
- Fields: user, password, root_fails_10m
- Additional fields:
    - mitre_id = ["T1110"]
    - reason = ["root brute burst (10m window)"]

AUTH_IP_OUTSIDE_ALLOWLIST_1
- What it detects: detects when RemoteIP is outside of allowlist
- Severity: unchanged
- Fields: ip
- Additional fields:
    - mitre_id = ["T1021.004"]
    - reason = ["source outside allowlist subnets ({ip})"]