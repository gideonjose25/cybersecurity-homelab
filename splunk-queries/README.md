# Splunk SPL Query Library

A reference collection of SPL queries used in SOC investigations.

## Queries

### Authentication Analysis

All failed logins
sourcetype="Soc_lab" status=failed
Rank attackers by failed login count
sourcetype="Soc_lab" status=failed | stats count by src_ip | sort -count
Successful logins only
sourcetype="Soc_lab" status=success
### Attack Timeline

Full activity for a specific IP
sourcetype="Soc_lab" src_ip=192.168.1.105 | sort _time

### Activity Summary
Count all actions across all events
sourcetype="Soc_lab" | stats count by action | sort -count
