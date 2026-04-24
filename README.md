# AI-Security-Log-Analyzer


This project is a Python-based SOC-style log analyzer that detects suspicious login activity from a sample log file.

## Project Highlights

- Built a SOC-style log analysis tool using Python
- Detected brute-force attacks using timestamp-based analysis
- Classified IP risk levels (High, Medium, Low)
- Generated automated security reports for incident response

## Future Improvements

- Integration with SIEM tools (Splunk)
- Real-time log monitoring
- Alert system via email/Slack

## Log Format

```txt
timestamp,IP,username,status**

Example:

2026-04-23 10:01:00,192.168.1.10,admin,FAILED

How to Run
python main.py  
