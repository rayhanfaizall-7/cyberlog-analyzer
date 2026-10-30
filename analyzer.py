import re

# Simple Security Log Analyzer & Threat Detector
# Designed for InfoSec Master's Portfolio

sample_logs = [
    "INFO: User admin logged in successfully from 192.168.1.10",
    "WARNING: Failed password attempt for user root from 45.33.32.156",
    "WARNING: Failed password attempt for user root from 45.33.32.156",
    "WARNING: Failed password attempt for user root from 45.33.32.156",
    "ALERT: Multiple failed login attempts detected from IP: 45.33.32.156",
    "WARNING: Failed password attempt for user admin from 198.51.100.42"
]

def analyze_logs(logs):
    print("[*] Starting Advanced Security Log Analysis...\n")
    
    threat_count = 0
    ip_counts = {}
    
    # Regular expression to find IPv4 addresses
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

    for log in logs:
        if "Failed password" in log or "ALERT" in log:
            print(f"[THREAT DETECTED] {log}")
            threat_count += 1
            
            # Extract IP address from the log line using regex
            match = re.search(ip_pattern, log)
            if match:
                ip = match.group()
                # Count occurrences per IP address
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

    print(f"\n[!] Analysis complete. Total threats found: {threat_count}")
    
    print("\n--- IP Threat Summary ---")
    for ip, count in ip_counts.items():
        print(f"IP: {ip} | Flagged Events: {count}")

if __name__ == "__main__":
    analyze_logs(sample_logs)