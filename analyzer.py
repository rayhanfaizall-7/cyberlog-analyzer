import re
import os
import argparse

# Advanced Security Log Analyzer & Threat Detector
# Designed for InfoSec Portfolio

def analyze_logs(file_path):
    print(f"[*] Opening security log file: {file_path}\n")
    
    if not os.path.exists(file_path):
        print(f"[!] Error: Log file '{file_path}' not found!")
        return

    threat_count = 0
    ip_counts = {}
    
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

if __name__ == "__main__":
    # Setup command-line argument parsing for professional CLI usage
    parser = argparse.ArgumentParser(description="Professional Security Log Analyzer & Threat Detector")
    parser.add_argument("logfile", help="Path to the log file to analyze")
    
    args = parser.parse_args()
    analyze_logs(args.logfile)
  