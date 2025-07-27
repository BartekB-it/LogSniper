# LogSniper

**LogSniper** is a lightweight security log parser built to detect and classify potential threats in system and web logs - such as failed logins, brute-force attempts, suspicious HTTP scanning, and privilege escalations.

## Project Goal

The main goal of this project is to develop a tool that:

- Parses system and web logs (`auth.log`, `syslog`, `access.log`)
- Detects and classifies selected security events
- Lays a foundation for future development into:
  - a honeypot,
  - a lightweight SIEM,
  - or a data source for threat hunting and blue teaming.

## How to Use

Parse authentication logs
python logsniper_auth.py logs/auth.log

Parse web server access logs
python logsniper_old.py logs/apache_shady.log

Results:

auth.log → results.csv

access.log → suspicious_entries.json

## Supported Events

# System Log Events (auth.log)

| Event Type            | Description                             | MITRE ATT\&CK ID |
| --------------------- | --------------------------------------- | ---------------- |
| FAILED\_LOGIN         | Failed login attempt                    | T1110.001        |
| BRUTE\_FORCE\_ATTEMPT | 5+ failed logins from same IP           | T1110            |
| SUDO\_USAGE           | Use of administrative privileges (sudo) | T1548            |
| SUCCESSFUL\_LOGIN     | Successful login                        | T1078            |

# Web Log Events (access.log)

| Event Type                           | Description                                          |
| ------------------------------------ | ---------------------------------------------------- |
| SQLMAP\_SCANNER                      | User-Agent contains `sqlmap`                         |
| CURL\_SCANNER                        | User-Agent is `curl`, indicating automation          |
| NIKTO\_SCANNER                       | Known Nikto scan pattern                             |
| STRANGE\_METHOD                      | Suspicious HTTP method (e.g., OPTIONS, HEAD, DELETE) |
| POTENTIAL\_BRUTEFORCE                | Repeated 403s to `/login`                            |
| POTENTIAL\_404\_FLOOD                | 20+ 404s from same IP                                |
| POTENTIAL\_SCAN                      | Multiple IPs probing same path                       |
| POTENTIAL\_SETUP\_CGI\_SCANNER       | Access to `setup.cgi`                                |
| POTENTIAL\_CONFIG\_PHP\_SCANNER      | Access to `config.php`                               |
| POTENTIAL\_SUSPICIOUS\_PATH\_SCANNER | Access to `/hidden` or similar paths                 |

## Project Structure

LogSniper/
│
├── logs/             # Sample log files for testing
├── src/              # Source code (parser, classifier, etc.)
├── doc/              # Notes, diagrams, sketches
├── README.md         # Project documentation

## Sample Input Log

Jul 24 22:10:01 server sshd[1234]: Failed password for user alice from 192.168.1.50 port 51412 ssh2

Parsed into:

[FAILED_LOGIN] Time: Jul 24 22:10:01, IP: 192.168.1.50, User: alice


## Detection Sources / Inspirations

- MITRE ATT&CK
- Sigma Rules
- GTFOBins
- Blue Team Cheat Sheet
- TryHackMe / Hack The Box Labs

## Author

Bartłomiej Biskupiak
This is part of my blue team / cybersecurity learning path.

## Project Status

**In development (MVP stage)** - weekly updates planned.

## Roadmap Components

- Log parser for auth.log - DONE

- Basic web log analysis from access.log - DONE

- Advanced detection rules (work in progress)

- SQLite or Elastic integration (optional, later)

- Weekly updates planned

## Contributing

Want to help? Open an issue or submit a pull request!
This is an educational project — all feedback is welcome.

This project is part of my public cybersecurity portfolio.
Started: July 2025