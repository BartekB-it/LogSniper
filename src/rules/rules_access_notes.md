ACCESS_401_403_BRUTE_FORCE_1
- What it detects: detects 4 or more 401 and 403 login attempts from 1 IP address within 10 minutes window
- Severity: +1
- Fields: status, ip, login_fail_window
- Additional fields:
    - mitre_id = ["T1110"]
    - reason = ["login fails on auth endpoint (10m): {fails_login_10m}"]

ACCESS_401_403_BRUTE_FORCE_2
- What it detects: detects 7 or more 401 or 403 attempts from 1 IP address within 10 minutes window
- Severity: +1
- Fields: status, ip, login_fail_window
- Additional fields:
    - reason = ["heavy login brute (auth endpoint)"]

ACCESS_HTTP_ERROR_BURST_1
- What it detects: detects 3 or more 401 or 403 or 404 attempts from 1 IP address within 10 minutes window
- Severity: +1
- Fields: status, ip, fail_window
- Additional fields: 
    - mitre_id = ["T1595.002", "T1190"]
    - reason = ["HTTP error burst - more than 2 attempts (10m window)"]

ACCESS_HTTP_ERROR_BURST_2
- What it detects: detects 5 or more 401 or 403 or 404 attempts from 1 IP address within 10 minutes window
- Severity: +1
- Fields: status, ip, fail_window
- Additional fields: 
    - reason = ["HTTP error burst - more than 4 attempts (10m window)"]

ACCESS_HTTP_ERROR_BURST_3
- What it detects: detects 10 or more 401 or 403 or 404 attempts from 1 IP address within 10 minutes window
- Severity: +1
- Fields: status, ip, fail_window
- Additional fields: 
    - reason = ["HTTP error burst - more than 9 attempts (10m window)"]

ACCESS_HIGH_REQ_COUNT_1
- What it detects: detects 100 or more requests from 1 IP address within 10 minutes window
- Severity: +1
- Fields: ip, req_window
- Additional fields:
    - mitre_id = ["T1595", "T1498.001"]
    - reason = ["high request rate per IP (10m window): {req_count_10m}"]

ACCESS_403_404_UNIQ_SCANNING_1
- What it detects: detects 15 or more 403 or 404 attempts on unique paths from 1 IP address within 10 minutes window
- Severity: +1
- Fields: status, ip, uniq_404_403_window
- Additional fields:
    - mitre_id = ["T1595.001"]
    - reason = ["enumeration burst: {uniq_cnt} distinct 404/403 (10m)"]

ACCESS_HTTP_403_403_ERROR_BURST_1
- What it detects: detects 10 or more 403 or 404 attempts from 1 IP address within 10 minutes window
- Severity: +1
- Fields: status, ip, error_burst_widnow
- Additional fields:
    - mitre_id = ["T1595.001"]
    - reason = ["HTTP error burst (404/403) - enumeration (10m): {errors_10m}"]

ACCESS_SUSPICIOUS_URL_1
- What it detects: connection attempt on one of suspicious URls ["phpmyadmin", "/etc/passwd", "/wp-login.php", "/admin", "/env", "/wp-admin", "/server-status", "/.git", "/config.php"]
- Severity: +1
- Fields: path
- Additional fields: 
    - mitre_id = ["T1190"]
    - reason = ["suspicious URl"]