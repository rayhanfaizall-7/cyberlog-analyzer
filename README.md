# 🛡️ Python Log Analyzer & Threat Detector

A lightweight, regex-powered security log analysis tool designed to ingest server logs, identify brute-force attacks, extract malicious IP addresses, and automatically export structured JSON threat reports. Built for cybersecurity portfolios and *Werkstudent* applications.

## 🚀 Features
- **External Log Ingestion**: Dynamically reads server log files line by line.
- **Regex IP Extraction**: Uses regular expressions to pinpoint IPv4 addresses associated with suspicious events.
- **Threat Detection Engine**: Flags failed password attempts and high-priority security alerts.
- **Command-Line Interface (CLI)**: Built with `argparse` for flexible, professional file analysis.
- **Automated Reporting**: Exports a structured JSON report (`threat_report.json`) containing timestamps, threat counts, and flagged IP summaries.

## 💻 Requirements
- Python 3.x

## 🛠️ How to Run
Run the script from your terminal by passing the target log file as an argument:
```bash
py analyzer.py server_logs.txt