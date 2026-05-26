# 🛡️ Cybersecurity Home Lab

Gideon Jose — Cybersecurity & IT Professional  

CompTIA Security+ | CCNA | 10+ years enterprise & Telecom experience | SOC Home Lab

---

## About This Lab

This repository documents my hands-on cybersecurity training journey as I transition from network engineering into a SOC Analyst role. Every exercise, finding, and tool is documented here — both as a portfolio for employers and as a resource for others making the same transition.

---

## Tools & Environment

- **OS:** Kali Linux 2026.1 (ARM64 via UTM on macOS)
- **SIEM:** Splunk Enterprise (Docker)
- **Network Analysis:** Wireshark, Nmap
- **Ticketing:** ServiceNow (Personal Developer Instance)
- **Training:** TryHackMe SOC Level 1 Path

---

## Lab Journal

| Date | Exercise | Tools | Key Finding |
|------|----------|-------|-------------|
| Apr 3, 2026 | Brute Force Investigation | TryHackMe SIEM | Malicious IP 221.181.185.159 — port 22 brute force → successful SSH login |
| Apr 4, 2026 | Alert Triage (3 alerts) | TryHackMe SIEM | True/False positive classification using context analysis |
| Apr 5, 2026 | SPL Log Analysis | Splunk | Detected brute force attack chain and post-exploitation /etc/passwd access |
| May 24, 2026 | Phishing Analysis Fundamentals | TryHackMe, CyberChef, Thunderbird | Email header analysis, base64 attachment decoding, display name spoofing detection |

## TryHackMe Progress

- ✅ Junior Security Analyst Intro
- ✅ SOC Role in Blue Team
- ✅ SOC Fundamentals
- ✅ SOC L1 Alert Triage
- ✅ SOC L1 Alert Reporting
- ✅ Phishing Analysis Fundamentals

---

### Lab 2 — OSINT IOC Enrichment | May 25, 2026
- Investigated malicious IP 185.220.101.47 using VirusTotal and AbuseIPDB
- Identified Tor exit node with 100% abuse confidence and 9 vendor detections
- Documented full Tier 1 SOC response workflow
- [View Lab](lab-journal/osint-ioc-investigation/lab-osint-ioc-investigation.md)


## Certifications

- CompTIA Security+ 
- Cisco CCNA
- BS Information Technology: Data Networking & Security — Liberty University (May 2028)

---

*Updated regularly as training progresses.*
