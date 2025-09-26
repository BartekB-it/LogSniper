# LogSniper

**⚠️ WIP / AI-assisted**

I built the core (parsing, the severity ladder, MITRE tagging, and the initial rules) myself. I drafted additional detections with the help of AI and am **currently validating and tuning them**. This release prioritizes a stable core and testable JSON outputs; the optional modules (geo, email alerts, dashboard) are **disabled by default**.

**LogSniper** is a lightweight security log parser that detects and classifies suspicious activity across Linux auth/sys logs, web access logs, and Windows EVTX (Security). It focuses on **clear, explainable rules**, sliding-window correlation, and a simple JSON output you can inspect or post-process.

## What’s in this release (core-only)

This version prioritizes a **stable, testable core**: parsing + detections + JSON results.
Optional modules (Geolocation, Email alerts, Streamlit dashboard) **exist in the repo** but are **not wired into the default pipeline** (details below).

Note: Several newer detection rules were drafted with AI assistance and are being validated; thresholds/allowlists may change.

## Supported inputs

- **Web access logs** (e.g., Apache/Nginx combined)

- **Linux auth logs** (e.g., auth.log)

- **Windows Security EVTX** (selected Event IDs)

- **Linux syslog**: (kernel, sudo, cron, systemd)

## How to Use

1. **Install Dependencies**:

```bash
pip install -r requirements.txt
```
2. **Run the main program**:
```bash
python main.py
```
Choose: access | auth | evtx | syslog

3. **Results**:

After processing, results are saved in the results/ folder as JSON files.

4. **Email Notifications Setup**:

To enable email notifications, create a .env file in the root directory with the following content:
```bash
EMAIL_USER=your_email_address@gmail.com
EMAIL_PASS=your_application_password
```
- The EMAIL_USER is your Gmail address.

- The EMAIL_PASS is an application-specific password generated in your Google account settings.

Once set up, the tool will send:

- **Brute-force alerts** when attacks are detected.

- **Analysis summary** after each scan.

5. **Results Visualization (NEW! - includes map view)**:

Explore and filter your results visually with the **Streamlit dashboard**.
```bash
streamlit run charts_app.py
```
- Select any JSON file from the results/ folder.

- View tables, filter by classification, see bar charts for detection types.

- **See the geographic origin of events on an interactive map** (no tokens needed).

- Works for all supported log types (including EVTX).

**To run the dashboard:**
```bash
streamlit run charts_app.py
```
- Select any JSON file from the results/ folder.

- View tables, filter by classification, and see bar charts for detection types.

- Works for all supported log types (including EVTX).

## Demo

Here's a quick demo of **LogSniper** in action:

![LogSniper Demo](assets/LogSniper.gif)

## Automated Testing with test_runner.py

The test_runner.py script automates testing of parsers for various log files in the test_logs/ folder, storing JSON results in results/.
```bash
python test_runner.py
```
This ensures that any new detection rules or parser updates are properly validated.

## Supported Events

### System Log Events (auth.log)

- **Failed password** bursts per IP (10m: >2, >4, >9). → T1110

- **High auth rate** (10m). → T1595, T1498.001

- **Targeted user** brute per IP+user (>4). → T1110

- **Accepted password after recent burst** (possible success after brute). → T1110, T1078

- **Invalid user** bursts; **root** attempts/success. → T1087.001, T1078

- Context: **outside allowlist** subnets tag. → T1021.004

### Web Log Events (access.log)

- **Auth endpoints**: 401/403 bursts per IP (10m), login brute at /login, /xmlrpc.php, etc. → T1110

- **High request-rate per IP** (10m). → T1595, T1498.001

- **404/403 enumeration**: many unique not-found paths (10m) and large error bursts. → T1595.001

- **Path/payload patterns**:

    - **SQLi** in query. → T1190

    - **Command injection** patterns in path/query. → T1059

    - **Traversal/LFI, secrets** (/.env, /.git, /config.php), **cloud metadata, JNDI, Spring/WordPress probes**. → T1190 / T1595 (as applicable)

- **UA anomalies**: curl, python-requests, sqlmap, nikto. → T1595, T1036.005

- **Dangerous/rare methods** (TRACE/PUT/DELETE/…); if **2xx**, escalate.

### Windows Event Logs (EVTX)

- **Brute-force / credential abuse**

    - **4625** Failed logon bursts per **source** and per **(source,user)**. → T1110

    - **4771** Kerberos pre-auth failures (per source / per (source,user)). → T1110

    - **4776** NTLM failures (per (workstation,user)). → T1110

- **Suspicious new sources / lateral movement hints**

    - **4624** Successful logon (type 3/10): **first-seen source** per user. → T1078

    - **4768** New Kerberos TGT source per user. → T1078

    - **5140/5145** SMB admin share access (ADMIN$, C$, IPC$) + **new SMB source** per user. → T1021.002

- **Privilege & account changes**

    - **4672** Special privileges **shortly after** 4624 (tight window). → T1078

    - **4720/4726** User created / deleted. → T1136, T1098

    - **4732** Added to privileged group (Domain Admins, Administrators, etc.). → T1098

- **Persistence / execution**

    - **7045** New service created (flags suspicious paths like AppData, Temp, ProgramData). → T1543.003

    - **4698** Scheduled task created (flags actions: powershell, cmd.exe, wscript, etc.). → T1053.005

- **Defense evasion**

    - **4719** Audit policy changed → T1562

    - **1102** Security log cleared → T1562 (auto-CRITICAL)

### Syslog

- **kernel (UFW/NFLOG)**

    - Burst per **SRC** in 10m window (>10, >25). → T1595.002

    - **Port scan** hint: many **unique DPT** per SRC in 10m (>7). → T1595.002

    - **Sensitive ports** focus (22/23/139/445/3389/5900/3306) per (src,dpt) (>5,>15). → T1595.001

    - Context: mark **external source** (non-RFC1918) once per window.

- **cron**

    - Suspicious command content/path (e.g., curl/wget, shell, /tmp, /dev/shm). → T1053.003 (+ T1105 if exfil/transfer hints)

    - **New cron user** (first-seen per host). → T1053.003

    - **Burst** of same user+cmd in 10m (>5, >15). → T1053.003

- **systemd**

    - **Failed** events per unit (repeated in 10m). → T1569.002

    - **Flapping**: many events per unit in short window (2m). → T1569.002, T1543.002

    - **New unit** started (first-seen per host), suspicious paths/names (e.g., /tmp/). → T1543.002

    - **Start/stop storms** in 10m (>=8). → T1543.002

- sudo

    - **First sudo** for a user (per repo runtime). → T1548.003

    - **Burst** per user in 10m (>3, >7). → T1548.003

    - **Many unique sudo commands** in 10m (>5). → T1548.003

    - **Sensitive commands** (e.g., systemctl, chmod/chown, useradd, tcpdump, curl/wget/...). → T1548.003

    - **Shell/interpreters** via sudo (bash, python, …). → T1059

    - **Non-interactive sudo** or **pam_unix auth failures** bursts. → T1548, T1110

## Project Structure
```bash
LogSniper/
│
├── test_logs/          # Sample log files for testing
├── results/            # Output files (JSON results)
├── src/                # Source code (analyzers, parsers, rules etc.)
├── main.py             # Main program entry point
├── test_runner.py      # Automated testing script
├── charts_app.py       # Visualization dashboard (NEW: map view!)
├── geo_api.py          # Geolocation enrichment module (NEW: lat/lon)
├── README.md           # Project documentation
```
## Sample Input Log
```bash
Jul 24 22:10:01 server sshd[1234]: Failed password for user alice from 192.168.1.50 port 51412 ssh2
```
Parsed into:
```bash
[FAILED_LOGIN] Time: Jul 24 22:10:01, IP: 192.168.1.50, User: alice
```

## Detection Sources / Inspirations

- MITRE ATT&CK
- Sigma Rules
- GTFOBins

## Author

Bartłomiej Biskupiak

This is part of my blue team / cybersecurity learning path.

## How this was built (short note)

- I wrote the **project structure, parsers, severity escalation, MITRE tagging**, and the initial rules.  
- I used **AI as a drafting assistant** to explore additional detections and refactors.  
- I’m now **validating and tuning each rule** (thresholds, allowlists, FP control) and will re-enable optional modules once the detection core is stable.

## Project Status

**In active development** – Most features are functional, with planned updates for new detection rules and integrations.

## Roadmap Components

- Log parser for auth.log - **DONE**

- Basic web log analysis from access.log - **DONE**

- EVTX log analysis - **DONE**

- Geolocation for all log types, with 40 requests/minute API limit - **DONE**

- Email notifications for brute-force detection and analysis reports - **DONE**

- IP geolocation map visualization – **DONE**

- Sys log analysis - **DONE**

- Severity levels of events - **DONE**

- Advanced detection rules - **DONE but will add more**

- Re-enable Geo/IP map + email alerts + dashboard after rule hardening - **In progress**

- SQLite or Elastic integration (optional, later)

## Contributing

Want to help? Open an issue or submit a pull request!

This is an educational project - all feedback is welcome.

This project is part of my public cybersecurity portfolio.

Started: July 2025