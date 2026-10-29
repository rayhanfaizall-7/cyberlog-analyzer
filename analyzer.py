# Simple Security Log Analyzer
# Designed for InfoSec Master's Portfolio

sample_logs = [
    "INFO: User admin logged in successfully from 192.168.1.10",
    "WARNING: Failed password attempt for user root from 45.33.32.156",
    "WARNING: Failed password attempt for user root from 45.33.32.156",
    "WARNING: Failed password attempt for user root from 45.33.32.156",
    "ALERT: Multiple failed login attempts detected from IP: 45.33.32.156"
]

def analyze_logs(logs):
    print("[*] Starting Security Log Analysis...\n")
    threat_count = 0
    
    for log in logs:
        if "Failed password" in log or "ALERT" in log:
            print(f"[THREAT DETECTED] {log}")
            threat_count += 1
            
    print(f"\n[*] Analysis complete. Total threats found: {threat_count}")

if __name__ == "__main__":
    analyze_logs(sample_logs)