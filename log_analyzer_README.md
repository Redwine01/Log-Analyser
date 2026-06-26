# 🛡️ Windows Log Analyzer — SOC Threat Detection Tool

**Author:** Gaurav Shakya  
**Skills:** Python, Windows Security Events, SIEM Concepts, Incident Response  
**Level:** Entry-Level SOC Analyst Tool

---

## 📌 About This Project

A Python-based **Windows Security Event Log analyzer** built to simulate how a **SOC L1 Analyst** detects threats by reviewing event logs.

This tool detects:
- 🚨 **Brute Force Attacks** (multiple failed logins from same IP)
- 🔑 **Privilege Escalation** (admin rights assigned to suspicious users)
- 👤 **Unauthorized Account Creation**
- 🗑️  **Audit Log Tampering** (Event ID 1102 — most suspicious!)
- ➕ **Users added to Admin/Security Groups**

---

## 🔍 Windows Event IDs Monitored

| Event ID | Description | Severity |
|----------|-------------|----------|
| 4624 | Successful Login | INFO |
| 4625 | Failed Login | MEDIUM |
| 4625 (x5+) | Brute Force Detected | **CRITICAL** |
| 4648 | Login with Explicit Credentials | MEDIUM |
| 4672 | Admin Privileges Assigned | **HIGH** |
| 4720 | New User Account Created | **HIGH** |
| 4726 | User Account Deleted | **HIGH** |
| 4732 | User Added to Security Group | **HIGH** |
| 4768 | Kerberos Auth Requested | INFO |
| 4776 | NTLM Auth Attempted | MEDIUM |
| 1102 | Audit Log Cleared | **CRITICAL** |

---

## 🚀 How to Run

```bash
# No extra libraries needed for demo mode
python3 log_analyzer.py
```

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════╗
║   WINDOWS LOG ANALYZER — by Gaurav Shakya        ║
║   SOC Threat Detection & Incident Response Tool  ║
╚══════════════════════════════════════════════════╝

[✓] Loaded 13 log entries

────────────────────────────────────────────────────────────
  📊 LOG SUMMARY
────────────────────────────────────────────────────────────
  Total Events Analyzed : 13
  Alerts Generated      : 5

  🚨 THREAT ALERTS (5 found)

  Alert #1  🔴 [CRITICAL]
  Event   : 🚨 BRUTE FORCE DETECTED — 6 failed attempts
  User    : administrator
  Source  : 10.0.0.99
  Time    : 2024-01-15 10:02:10

  Alert #2  🟠 [MEDIUM]
  Event   : 🔑 Special Privileges Assigned (Admin)
  User    : unknown_user
  Source  : 10.0.0.99

  Alert #3  🟠 [HIGH]
  Event   : 🚨 Audit Log Cleared (Suspicious!)
  User    : hacker123
  Source  : 10.0.0.99
```

---

## 📁 Output Files Generated

| File | Description |
|------|-------------|
| `threat_report.log` | Human-readable alert report |
| `threat_report.csv` | For Excel/SIEM import |
| `threat_report.json` | For API/dashboard integration |

---

## 🔐 Real-World SOC Use Case

> In a real SOC environment, analysts review Windows Security Event Logs daily to catch:
> - Login anomalies (brute force, off-hours logins)
> - Privilege misuse (unexpected admin assignments)
> - Evidence of tampering (log clearing = attacker covering tracks)
>
> This tool simulates the **triage phase** of SOC L1 operations.

---

## 🔧 Extend This Project

- [ ] Parse real `.evtx` files using `pyevtx-rs`
- [ ] Add email alerts for CRITICAL events
- [ ] Build a web dashboard using Flask
- [ ] Integrate with Splunk/ELK Stack

---

## 📚 What I Learned

- Windows Security Event ID mapping
- Brute force detection logic
- Log analysis methodology used in real SOC environments
- Python file I/O (LOG, CSV, JSON output)
- Debugging library compatibility issues (`python-evtx` vs `pyevtx-rs`)

---

## 👤 Author

**Gaurav Shakya**  
BCA Student | Aspiring SOC Analyst  
📧 gsha30963@gmail.com  
🔗 [LinkedIn](https://linkedin.com/in/gaurav-shakya-30963a2b0) | [GitHub](https://github.com/gauravshakya)
