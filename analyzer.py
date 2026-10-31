import re
import os
import argparse
import json
from datetime import datetime

# Advanced Security Log Analyzer & Threat Detector
# Designed for InfoSec Portfolio

def analyze_logs(file_path):
    print(f"[*] Opening security log file: {file_path}\n")
    
    if not os.path.exists(file_path):
        print(f"[!] Error: Log file '{file_path}' not found!")
        return

    threat_count = 0
    ip_counts = {}
    flagged_events = []
    
    # Regular expression to find IPv4 addresses
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

    # Open and read the external log file line by line
    with open(file_path, "r") as file:
        logs = file.readlines()

    for log in logs:
        log = log.strip()
        
        if "Failed password" in log or "ALERT" in log:
            print(f"[THREAT DETECTED] {log}")
            threat_count += 1
            flagged_events.append(log)
            
            # Extract IP address from the log line using regex
            match = re.search(ip_pattern, log)
            if match:
                ip = match.group()
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

    print(f"\n[!] Analysis complete. Total threats found: {threat_count}")
    
    print("\n--- IP Threat Summary ---")
    if ip_counts:
        for ip, count in ip_counts.items():
            print(f"IP: {ip} | Flagged Events: {count}")
    else:
        print("No malicious IPs detected.")

    # Prepare structured report dictionary
    report_data = {
        "scan_timestamp": str(datetime.now()),
        "source_log_file": file_path,
        "total_threats_found": threat_count,
        "ip_threat_summary": ip_counts,
        "detected_events": flagged_events
    }

    # Export report to JSON file
    report_filename = "threat_report.json"
    with open(report_filename, "w") as json_file:
        json.dump(report_data, json_file, indent=4)
    
    print(f"\n[+] Professional report successfully exported to {report_filename}")

if __name__ == "__main__":
    # Setup command-line argument parsing for professional CLI usage
    parser = argparse.ArgumentParser(description="Professional Security Log Analyzer & Threat Detector")
    parser.add_argument("logfile", help="Path to the log file to analyze")
    
    args = parser.parse_args()
    analyze_logs(args.logfile)