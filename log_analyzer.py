#!/usr/bin/env python3
"""
Windows Log Analyzer — SOC Threat Detection Tool
Author: Gaurav Shakya
GitHub: github.com/gauravshakya
Description: Parses Windows Security Event Logs to detect
             suspicious logins, brute force, and privilege escalation
"""

import json
import csv
import os
import datetime
from collections import defaultdict, Counter

# ─────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5       # Failed logins before alert
OUTPUT_LOG            = "threat_report.log"
OUTPUT_CSV            = "threat_report.csv"
OUTPUT_JSON           = "threat_report.json"

# ─────────────────────────────────────────────
#  WINDOWS SECURITY EVENT IDs
# ─────────────────────────────────────────────
EVENT_IDS = {
    "4624" : "✅ Successful Login",
    "4625" : "❌ Failed Login",
    "4648" : "⚠️  Login with Explicit Credentials",
    "4672" : "🔑 Special Privileges Assigned (Admin)",
    "4720" : "👤 New User Account Created",
    "4726" : "🗑️  User Account Deleted",
    "4732" : "➕ User Added to Security Group",
    "4768" : "🎫 Kerberos Auth Ticket Requested",
    "4776" : "🔐 NTLM Auth Attempted",
    "1102" : "🚨 Audit Log Cleared (Suspicious!)",
}

CRITICAL_EVENTS = ["4720", "4726", "4732", "1102", "4672"]

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────
def print_banner():
    print("""
╔══════════════════════════════════════════════════╗
║   WINDOWS LOG ANALYZER — by Gaurav Shakya        ║
║   SOC Threat Detection & Incident Response Tool  ║
╚══════════════════════════════════════════════════╝
    """)

# ─────────────────────────────────────────────
#  GENERATE SAMPLE LOG DATA (for demo/testing)
# ─────────────────────────────────────────────
def generate_sample_logs():
    """
    Simulates Windows Security Event Log entries.
    In real use, replace with actual Windows EVTX parsed data.
    """
    sample_logs = [
        # Normal logins
        {"EventID": "4624", "TimeCreated": "2024-01-15 08:30:00", "TargetUserName": "gaurav", "IpAddress": "192.168.1.5", "LogonType": "2"},
        {"EventID": "4624", "TimeCreated": "2024-01-15 09:00:00", "TargetUserName": "admin",  "IpAddress": "192.168.1.1", "LogonType": "2"},

        # Failed login attempts (Brute Force Simulation)
        {"EventID": "4625", "TimeCreated": "2024-01-15 10:01:00", "TargetUserName": "administrator", "IpAddress": "10.0.0.99", "LogonType": "3"},
        {"EventID": "4625", "TimeCreated": "2024-01-15 10:01:15", "TargetUserName": "administrator", "IpAddress": "10.0.0.99", "LogonType": "3"},
        {"EventID": "4625", "TimeCreated": "2024-01-15 10:01:30", "TargetUserName": "administrator", "IpAddress": "10.0.0.99", "LogonType": "3"},
        {"EventID": "4625", "TimeCreated": "2024-01-15 10:01:45", "TargetUserName": "administrator", "IpAddress": "10.0.0.99", "LogonType": "3"},
        {"EventID": "4625", "TimeCreated": "2024-01-15 10:02:00", "TargetUserName": "administrator", "IpAddress": "10.0.0.99", "LogonType": "3"},
        {"EventID": "4625", "TimeCreated": "2024-01-15 10:02:10", "TargetUserName": "administrator", "IpAddress": "10.0.0.99", "LogonType": "3"},

        # Privilege escalation
        {"EventID": "4672", "TimeCreated": "2024-01-15 10:05:00", "TargetUserName": "unknown_user", "IpAddress": "10.0.0.99", "LogonType": "3"},

        # New suspicious user created
        {"EventID": "4720", "TimeCreated": "2024-01-15 10:10:00", "TargetUserName": "hacker123", "IpAddress": "10.0.0.99", "LogonType": ""},

        # User added to admin group
        {"EventID": "4732", "TimeCreated": "2024-01-15 10:11:00", "TargetUserName": "hacker123", "IpAddress": "10.0.0.99", "LogonType": ""},

        # Audit log cleared — very suspicious
        {"EventID": "1102", "TimeCreated": "2024-01-15 10:15:00", "TargetUserName": "hacker123", "IpAddress": "10.0.0.99", "LogonType": ""},

        # Normal activity continues
        {"EventID": "4624", "TimeCreated": "2024-01-15 11:00:00", "TargetUserName": "gaurav", "IpAddress": "192.168.1.5", "LogonType": "2"},
        {"EventID": "4768", "TimeCreated": "2024-01-15 11:05:00", "TargetUserName": "gaurav", "IpAddress": "192.168.1.5", "LogonType": ""},
    ]
    return sample_logs

# ─────────────────────────────────────────────
#  ANALYZE LOGS
# ─────────────────────────────────────────────
def analyze_logs(logs):
    alerts        = []
    failed_logins = defaultdict(list)   # Track by IP
    stats         = Counter()

    for entry in logs:
        event_id  = entry.get("EventID", "")
        user      = entry.get("TargetUserName", "Unknown")
        ip        = entry.get("IpAddress", "N/A")
        timestamp = entry.get("TimeCreated", "N/A")
        desc      = EVENT_IDS.get(event_id, f"Unknown Event {event_id}")

        stats[event_id] += 1

        # ── Track failed logins per IP ──
        if event_id == "4625":
            failed_logins[ip].append({
                "user": user,
                "time": timestamp
            })

        # ── Alert on Critical Events ──
        if event_id in CRITICAL_EVENTS:
            alerts.append({
                "severity" : "HIGH" if event_id in ["1102", "4726"] else "MEDIUM",
                "event_id" : event_id,
                "event"    : desc,
                "user"     : user,
                "ip"       : ip,
                "timestamp": timestamp
            })

    # ── Brute Force Detection ──
    for ip, attempts in failed_logins.items():
        if len(attempts) >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "severity" : "CRITICAL",
                "event_id" : "4625-BF",
                "event"    : f"🚨 BRUTE FORCE DETECTED — {len(attempts)} failed attempts",
                "user"     : attempts[0]["user"],
                "ip"       : ip,
                "timestamp": attempts[-1]["time"]
            })

    return alerts, stats, failed_logins

# ─────────────────────────────────────────────
#  DISPLAY RESULTS
# ─────────────────────────────────────────────
def display_results(logs, alerts, stats):
    print(f"{'─'*60}")
    print(f"  📊 LOG SUMMARY")
    print(f"{'─'*60}")
    print(f"  Total Events Analyzed : {len(logs)}")
    print(f"  Alerts Generated      : {len(alerts)}")
    print(f"\n  Event Breakdown:")
    for eid, count in stats.most_common():
        name = EVENT_IDS.get(eid, f"Unknown ({eid})")
        print(f"    {eid:<6} {name:<40} x{count}")

    if not alerts:
        print("\n  [✓] No threats detected.")
        return

    print(f"\n{'─'*60}")
    print(f"  🚨 THREAT ALERTS ({len(alerts)} found)")
    print(f"{'─'*60}")
    for i, alert in enumerate(alerts, 1):
        sev = alert['severity']
        icon = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡"
        print(f"\n  Alert #{i}  {icon} [{sev}]")
        print(f"  Event   : {alert['event']}")
        print(f"  User    : {alert['user']}")
        print(f"  Source  : {alert['ip']}")
        print(f"  Time    : {alert['timestamp']}")

# ─────────────────────────────────────────────
#  SAVE REPORT
# ─────────────────────────────────────────────
def save_report(logs, alerts, stats):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── LOG file ──
    with open(OUTPUT_LOG, "w") as f:
        f.write(f"WINDOWS LOG ANALYZER — THREAT REPORT\n")
        f.write(f"Generated : {ts}\n")
        f.write(f"Events    : {len(logs)}\n")
        f.write(f"Alerts    : {len(alerts)}\n")
        f.write("=" * 60 + "\n\n")

        for i, alert in enumerate(alerts, 1):
            f.write(f"Alert #{i} [{alert['severity']}]\n")
            f.write(f"  Event : {alert['event']}\n")
            f.write(f"  User  : {alert['user']}\n")
            f.write(f"  IP    : {alert['ip']}\n")
            f.write(f"  Time  : {alert['timestamp']}\n\n")

    # ── CSV file ──
    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["severity","event_id","event","user","ip","timestamp"])
        writer.writeheader()
        writer.writerows(alerts)

    # ── JSON file ──
    report = {
        "generated_at": ts,
        "total_events" : len(logs),
        "total_alerts" : len(alerts),
        "alerts"       : alerts
    }
    with open(OUTPUT_JSON, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\n[✓] Reports saved:")
    print(f"    → {OUTPUT_LOG}")
    print(f"    → {OUTPUT_CSV}")
    print(f"    → {OUTPUT_JSON}")

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    print_banner()

    print("[*] Loading Windows Event Logs (sample data)...")
    print("[!] For real use: parse EVTX files using python-evtx library\n")

    logs = generate_sample_logs()
    print(f"[✓] Loaded {len(logs)} log entries\n")

    alerts, stats, failed_logins = analyze_logs(logs)

    display_results(logs, alerts, stats)
    save_report(logs, alerts, stats)

    print("\n[✓] Analysis complete!\n")

if __name__ == "__main__":
    main()
