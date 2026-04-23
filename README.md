# AI-Security-Log-Analyzer


This project is a Python-based SOC-style log analyzer that detects suspicious login activity from a sample log file.

## Features

- Reads login logs from `sample_log.txt`
- Detects failed and successful login attempts
- Identifies high-risk IP addresses
- Detects possible brute-force attacks
- Uses timestamp-based detection for multiple failed logins within 1 minute
- Generates a security report in `report.txt`

## Log Format

```txt
timestamp,IP,username,status**

Example:

2026-04-23 10:01:00,192.168.1.10,admin,FAILED

How to Run
python main.py  
