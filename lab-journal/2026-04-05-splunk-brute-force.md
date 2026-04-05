# Splunk SPL Investigation: Brute Force Attack
**Date:** April 5, 2026  
**Tool:** Splunk Enterprise (Docker)  
**Difficulty:** Beginner  
**Time:** ~45 minutes

---

## Scenario

As a SOC L1 Analyst, I ingested a custom log file into Splunk containing simulated authentication and file access events across multiple hosts. My objective was to identify malicious activity using SPL queries.

---

## Environment

- Splunk Enterprise running via Docker on Kali Linux
- Log file: `soc_lab.log` (10 events, uploaded via Splunk Web UI)
- Sourcetype: `Soc_lab`

---

## SPL Queries & Findings

### Query 1 — Find All Failed Logins

sourcetype="Soc_lab" status=failed
**Result:** 6 failed login events returned across 2 source IPs.

### Query 2 — Rank Attackers by Failed Login Count

sourcetype="Soc_lab" status=failed | stats count by src_ip | sort -count
**Result:**

| src_ip | count |
|--------|-------|
| 192.168.1.105 | 4 |
| 203.0.113.45 | 2 |

### Query 3 — Full Attack Timeline for Top Attacker

sourcetype="Soc_lab" src_ip=192.168.1.105 | sort _time
**Result:** Complete attack chain revealed in chronological order.

### Query 4 — Action Summary Across All Events

sourcetype="Soc_lab" | stats count by action | sort -count
**Result:**

| action | count |
|--------|-------|
| login | 8 |
| file_access | 1 |
| file_download | 1 |

---

## Attack Chain Identified

| Time | Event |
|------|-------|
| 22:00:01 | Failed login — admin@webserver01 |
| 22:00:03 | Failed login — admin@webserver01 |
| 22:00:05 | Failed login — admin@webserver01 |
| 22:00:07 | Failed login — admin@webserver01 |
| 22:00:09 | **Successful login** — brute force succeeded |
| 22:01:00 | **File access: /etc/passwd** — credential harvesting |

---

## Verdict

**True Positive — Brute Force Attack with Post-Exploitation Activity**

- Attacker `192.168.1.105` brute forced the admin account on `webserver01`
- After 4 failed attempts, login succeeded at 22:00:09
- Immediately accessed `/etc/passwd` — classic credential harvesting
- External IP `203.0.113.45` also attempted logins on `dc01` — 2 failed, no success

---

## Key Takeaways

- SPL `stats count by` is essential for identifying top threat sources quickly
- Sorting by `_time` reveals attack progression and post-exploitation behavior
- `/etc/passwd` access after a brute force is a strong indicator of privilege escalation intent
- Always investigate what happens AFTER a successful login, not just the login itself
