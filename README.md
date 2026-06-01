# 🛡️ Cybersecurity Home Lab

Gideon Jose — Cybersecurity & IT Professional  

CompTIA Security+ | CCNA | 10+ years enterprise & Telecom experience | SOC Home Lab

---

## About This Lab

This repository documents my hands-on cybersecurity training journey as I work as a Data Center Technician and build toward a SOC Analyst role. Every OSINT investigation, threat analysis, Splunk query, and tool exercise is documented here — both as a portfolio for employers and as a resource for anyone trying to break into IT and cybersecurity.

---

## Tools & Environment

- **OS:** Kali Linux (ARM64 via UTM on macOS)
- **SIEM:** Splunk Enterprise (Docker)
- **Threat Intelligence:** VirusTotal, AbuseIPDB
- **Network Analysis:** Wireshark, Nmap
- **Ticketing:** ServiceNow (Personal Developer Instance)
- **Training:** TryHackMe SOC Level 1 Path / Hack The Box
- **Certifications:** CompTIA Security+ (DoD 8570) | Cisco CCNA

---

## Lab Journal

| Date | Exercise | Tools | Key Finding |
|------|----------|-------|-------------|
| Apr 3, 2026 | Brute Force Investigation | TryHackMe SIEM | Malicious IP 221.181.185.159 — port 22 brute force → successful SSH login |
| Apr 4, 2026 | Alert Triage (3 alerts) | TryHackMe SIEM | True/False positive classification using context analysis |
| Apr 5, 2026 | SPL Log Analysis | Splunk | Detected brute force attack chain and post-exploitation /etc/passwd access |
| May 24, 2026 | Phishing Analysis Fundamentals | TryHackMe, CyberChef, Thunderbird | Email header analysis, base64 attachment decoding, display name spoofing detection |
| May 31, 2026 | OSINT Multi-IP Investigation | VirusTotal, AbuseIPDB | 3 IPs investigated — 1 confirmed malicious (194.165.16.11), bulletproof hosting identified |

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

---

### Lab 3 — OSINT Multi-IP Investigation | May 31, 2026
- Investigated 3 IPs using VirusTotal and AbuseIPDB
- 2 clean verdicts + 1 confirmed malicious (194.165.16.11)
- Identified bulletproof hosting infrastructure (Flyservers S.A.)
- Documented discrepancy analysis between threat intel sources
- [View Lab](lab-journal/osint-multi-ip-investigation/lab3-osint-multi-ip-investigation.md)

## Certifications

- CompTIA Security+ 
- Cisco CCNA
- BS Information Technology: Data Networking & Security — Liberty University (May 2028)

---

*Updated regularly as training progresses.*
