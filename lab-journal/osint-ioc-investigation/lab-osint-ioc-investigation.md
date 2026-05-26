# Lab: OSINT IOC Enrichment — Investigating a Malicious IP Address

**Date:** May 25, 2026  
**Author:** Gideon Jose  
**Lab Environment:** Home SOC Lab | MacBook Pro M3 Pro  
**Difficulty:** Tier 1 SOC Analyst  
**Category:** Threat Intelligence | OSINT | IOC Analysis

---

## Objective

Practice the Tier 1 SOC analyst workflow for investigating a suspicious IP address using two open-source threat intelligence platforms — VirusTotal and AbuseIPDB — to determine whether an IOC (Indicator of Compromise) poses a threat and document actionable findings.

---

## Tools Used

| Tool | Purpose | URL |
|------|---------|-----|
| VirusTotal | Multi-vendor malware/IP reputation scan | virustotal.com |
| AbuseIPDB | IP abuse reports & confidence scoring | abuseipdb.com |

---

## Scenario

**IOC Under Investigation:** `185.220.101.47`

A suspicious IP address was flagged for investigation. The task was to enrich this IOC using open-source intelligence (OSINT) tools and determine its threat classification.

---

## Investigation Steps

### Step 1 — VirusTotal Analysis

Submitted `185.220.101.47` to VirusTotal for multi-vendor reputation check.

**Findings:**

- **Tagged as:** TOR — identified as a Tor exit node used to anonymize malicious traffic
- **ASN:** AS60729 — Stiftung Erneuerbare Freiheit (German autonomous system)
- **Country:** Germany 🇩🇪
- **Last analyzed:** 14 hours prior — active and current threat

**Vendor Detections:**

| Vendor | Verdict |
|--------|---------|
| Abusix | Malicious |
| ADMINUSLabs | Malicious |
| BitDefender | Phishing |
| G-Data | Phishing |
| GreyNoise | Malicious |
| Sophos | Malware |
| SOCRadar | Phishing |
| VIPRE | Malware |
| Webroot | Malicious |

**9 independent vendors** flagged this IP across three threat categories: Malicious, Phishing, and Malware.

---

### Step 2 — AbuseIPDB Cross-Validation

Submitted the same IP to AbuseIPDB for independent corroboration.

**Findings:**

| Field | Value |
|-------|-------|
| Abuse Confidence Score | **100%** |
| Total Reports | **6,551** |
| ISP | Network for Tor-Exit Traffic |
| ASN | AS60729 |
| Hostname | tor-exit-47.for-privacy.net |
| Domain | for-privacy.net |
| Country | Germany 🇩🇪 |
| City | Berlin, State of Berlin |
| Usage Type | Commercial |

> **Note:** AbuseIPDB confirmed this is a **Tor exit node**. The owner/provider is not directly responsible for the offending traffic — Tor exit nodes are used to anonymize the true origin of attack traffic.

---

## Consolidated IOC Profile

| Source | Verdict | Confidence |
|--------|---------|-----------|
| VirusTotal | 🔴 Malicious / Phishing / Malware | 9 vendor detections |
| AbuseIPDB | 🔴 Malicious | 100% confidence, 6,551 reports |

**Threat Classification:** HIGH — Confirmed malicious Tor exit node with maximum abuse confidence and multi-vendor corroboration.

---

## Analyst Notes

- Both OSINT tools independently confirmed the same verdict — this is a **high-fidelity, high-confidence IOC**.
- Tor exit nodes are commonly leveraged by threat actors for **brute force attacks, port scanning, credential stuffing, C2 communication, and phishing campaigns** because they obscure the attacker's true IP.
- The 6,551 AbuseIPDB reports indicate **sustained, ongoing malicious activity** — not a one-time incident.
- The 100% abuse confidence score means every analyst who reviewed this IP flagged it as abusive.

---

## Recommended SOC Response (Simulated)

If this IP appeared in an organization's firewall or SIEM logs, the Tier 1 recommended response would be:

1. **Block the IP** at the perimeter firewall immediately
2. **Isolate any internal host** that communicated with this IP
3. **Search SIEM logs** (e.g., Splunk) for all traffic to/from this IP — establish timeline
4. **Open an incident ticket** in ServiceNow with full IOC details
5. **Escalate to Tier 2** — Tor exit node communication is a serious indicator of compromise requiring deeper investigation
6. **Document and report** findings per IR playbook

---

## Skills Demonstrated

- Open-source threat intelligence (OSINT) enrichment
- Multi-source IOC validation workflow
- Tor exit node identification and threat classification
- SOC Tier 1 decision-making and escalation criteria
- Incident documentation practices

---

## Key Takeaways

> A single OSINT tool is a data point. Two corroborating sources are a conclusion.

This lab reinforced the importance of **cross-validating IOCs across multiple platforms** before acting. VirusTotal provides vendor-based reputation data; AbuseIPDB provides community-sourced abuse reports. Together, they give a Tier 1 analyst the confidence needed to escalate or block without hesitation.

Understanding Tor exit nodes is also critical — while the IP owner isn't responsible, **any internal host communicating with a known Tor exit node is a red flag** that warrants immediate investigation.

---

*Part of the [Gideon Jose Cybersecurity Home Lab](https://gideonjose25.github.io/cybersecurity-homelab) portfolio.*
