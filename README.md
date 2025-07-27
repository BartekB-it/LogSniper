# LogSniper

**LogSniper** is a simple system log parser designed to classify potential security threats such as failed logins, brute-force attempts, and administrative privilege usage.

## Project Goal

The goal of this project is to build a tool that:
- Loads and parses system logs (e.g., 'auth.log', 'syslog', 'access.log')
- Detects and classifies selected security events
- Can serve as a foundation for future development into a honeypot, SIEM, or a threat hunting data source

## How to Use

python logsniper_auth.py logs/auth.log
or
python logsniper_old.py logs/apache.log

The results for auth.log will be saved in results.csv in the same folder

## Supported Events (MVP)

| Event Type            | Description                                 | MITRE ID  |
| --------------------- | ------------------------------------------- | --------- |
| FAILED_LOGIN          | Failed login attempts                       | T1110.001 |
| BRUTE_FORCE_ATTEMPT   | 5 failed attempts from the same IP          | T1110     |
| SUDO_USAGE            | Usage of administrative privileges (`sudo`) | T1548     |
| SUCCESSFUL_LOGIN      | Successful login                            | T1078     |

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


## Inspirations

- MITRE ATT&CK
- Sigma Rules
- GTFOBins
- Blue Team Cheat Sheet
- TryHackMe / Hack The Box Labs

## Author

Name: Bartłomiej Biskupiak
This is part of my blue team / cybersecurity learning path.

## Project Status

**In development (MVP stage)** - weekly updates planned.

## Roadmap Components

- Log parser for auth.log - DONE

- Support for access.log and web logs - DONE

- Detection rules for unusual login hours

- SQLite or Elastic integration (optional)

## Contributing

Want to help? Open an issue or submit a pull request!
This is an educational project — all feedback is welcome.

This project is part of my public cybersecurity portfolio.
Started: July 2025