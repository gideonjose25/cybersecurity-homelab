# Lab 3: OSINT IOC Investigation — Multi-IP Threat Analysis

**Date:** May 31, 2026
**Author:** Gideon Jose
**Lab Environment:** Home SOC Lab | MacBook Pro
**Difficulty:** Tier 1 SOC Analyst
**Category:** Threat Intelligence | OSINT | IOC Analysis

---

## Objective

Practice the complete Tier 1 SOC analyst OSINT workflow by investigating three suspicious IP addresses using VirusTotal and AbuseIPDB. The goal is to triage, classify, and document each IP — demonstrating that effective SOC analysis requires making confident decisions across a range of outcomes, including clean, suspicious, and confirmed malicious indicators.

---

## Tools Used

| Tool | Purpose | URL |
|------|---------|-----|
| VirusTotal | Multi-vendor malware/IP reputation scan | virustotal.com |
| AbuseIPDB | IP abuse reports & confidence scoring | abuseipdb.com |

---

## Key Analyst Insight

> In real SOC environments, most alerts and suspicious IPs investigated will be **false positives or benign infrastructure.** A skilled Tier 1 analyst must be just as confident clearing an IP as flagging one. Tonight's investigation reflects that reality — two clean IPs and one confirmed threat.

---

## Investigation 1 — 185.234.219.80

### Step 1 — VirusTotal
- **Verdict:** ✅ Clean
- **Detections:** 0/91 vendors flagged
- **Community Score:** Neutral
- **ASN:** AS211415 — Karolio IT paslaugos, UAB
- **Country:** 🇦🇹 Austria

### Step 2 — AbuseIPDB
- **Verdict:** ✅ Clean
- **Abuse Confidence:** 0%
- **Total Reports:** 0
- **ISP:** Karolio IT paslaugos, UAB
- **Usage Type:** Data Center/Web Hosting/Transit
- **Domain:** simoresta.lt
- **Country:** Austria (Vienna)

### Analyst Verdict
**CLEAN — No Action Required**

Both sources returned zero detections and zero abuse reports. This IP is associated with a legitimate Data Center/Web Hosting provider in Austria. No indicators of compromise detected.

**SOC Disposition:** Clear and close. Document for audit trail.

---

## Investigation 2 — 91.92.109.45

### Step 1 — VirusTotal
- **Verdict:** ✅ Clean
- **Detections:** 0/91 vendors flagged
- **Community Score:** Neutral
- **ASN:** AS34224 — Neterra Ltd.
- **Country:** 🇧🇬 Bulgaria

### Step 2 — AbuseIPDB
- **Verdict:** ✅ Clean
- **Abuse Confidence:** 0%
- **Total Reports:** 0
- **ISP:** VPS.BG
- **Usage Type:** Data Center/Web Hosting/Transit
- **Domain:** vps.bg
- **Country:** Bulgaria (Sofia)

### Analyst Verdict
**CLEAN — No Action Required**

Both sources returned zero detections and zero abuse reports. This IP belongs to VPS.BG, a legitimate Bulgarian hosting provider. No indicators of compromise detected.

**SOC Disposition:** Clear and close. Document for audit trail.

---

## Investigation 3 — 194.165.16.11

### Step 1 — VirusTotal
- **Verdict:** 🔴 Malicious
- **Detections:** 14/91 vendors flagged
- **Last Analyzed:** 4 days ago — active threat
- **Community Score:** -19
- **ASN:** AS48721 — Flyservers S.A.
- **Country:** 🇱🇹 Lithuania
- **Tags:** suspicious-udp

**Vendor Detections:**

| Vendor | Verdict |
|--------|---------|
| ADMINUSLabs | Malicious |
| alphaMountain.ai | Malicious |
| BitDefender | Phishing |
| Chong Lua Dao | Malicious |
| CRDF | Malicious |
| Criminal IP | Malicious |
| CyRadar | Malware |
| Fortinet | Malware |
| G-Data | Phishing |
| Lionic | Malicious |
| SOCRadar | Phishing |
| Sophos | Malware |
| VIPRE | Malware |
| Webroot | Malicious |
| GreyNoise | Suspicious |

### Step 2 — AbuseIPDB
- **Verdict:** 🟡 Suspicious
- **Abuse Confidence:** 48%
- **Total Reports:** 19,050
- **ISP:** Flyservers S.A.
- **Usage Type:** Data Center/Web Hosting/Transit
- **Hostname:** ptr.flow-metric.com
- **Domain:** flyservers.com
- **Country:** Lithuania (Vilnius)

### Analyst Notes — Discrepancy Analysis

An important analytical observation: VirusTotal returned strong malicious signals (14 vendors) while AbuseIPDB showed only 48% confidence despite 19,050 reports. This discrepancy warrants deeper analysis.

**Why the discrepancy?**
- 19,050 reports with only 48% confidence suggests **mixed activity** — some legitimate traffic exists alongside malicious behavior
- The "suspicious-udp" tag indicates **port scanning or UDP-based attack traffic**
- **Flyservers S.A.** is a known bulletproof hosting provider frequently leveraged by threat actors to host malicious infrastructure while maintaining plausible deniability
- The negative community score (-19) on VirusTotal reinforces the malicious classification

### Analyst Verdict
**MEDIUM-HIGH RISK — Block and Monitor**

While AbuseIPDB confidence is not at 100%, the combination of 14 vendor detections on VirusTotal, 19,050 abuse reports, bulletproof hosting infrastructure, and active threat status (analyzed 4 days ago) presents sufficient evidence to treat this IP as a threat.

**SOC Disposition:**
1. Block IP at perimeter firewall immediately
2. Search SIEM logs for any internal hosts that communicated with this IP
3. If internal communication found — isolate the host and escalate to Tier 2
4. Open incident ticket in ServiceNow
5. Document findings and IOC for threat intelligence repository

---

## Consolidated IOC Summary

| IP Address | VirusTotal | AbuseIPDB | Final Verdict | Action |
|------------|-----------|-----------|---------------|--------|
| 185.234.219.80 | ✅ 0/91 | ✅ 0% | Clean | Close |
| 91.92.109.45 | ✅ 0/91 | ✅ 0% | Clean | Close |
| 194.165.16.11 | 🔴 14/91 | 🟡 48% | Malicious | Block & Escalate |

---

## Skills Demonstrated

- Multi-IP OSINT triage workflow
- Cross-source IOC validation (VirusTotal + AbuseIPDB)
- Analyst judgment — confident disposition across clean and malicious outcomes
- Discrepancy analysis between threat intelligence sources
- Bulletproof hosting infrastructure identification
- SOC Tier 1 response documentation

---

## Key Takeaways

> Most IPs you investigate in a SOC will be clean. The ability to confidently clear false positives is just as important as detecting real threats. Tonight's investigation demonstrates the complete analyst workflow — triage, investigate, classify, document, and act.

The discrepancy between VirusTotal and AbuseIPDB on IP 194.165.16.11 highlights a critical analyst skill: **when two sources disagree, investigate further rather than defaulting to either verdict.** Context — hosting provider reputation, community score, tags, and recency — drives the final decision.

---

*Part of the [Gideon Jose Cybersecurity Home Lab](https://gideonjose25.github.io/cybersecurity-homelab) portfolio.*
