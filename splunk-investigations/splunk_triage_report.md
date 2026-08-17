# Incident Report: Endpoint Triage & Sysmon Log Analysis

## 1. Incident Overview
* **Incident ID:** IR-2026-0816-SPL
* **Platform:** Splunk Enterprise (Sysmon Telemetry)
* **Severity:** High
* **Threat:** Malicious Encoded PowerShell Execution via Spear-Phishing Ingress

---

## 2. Investigation & SPL Queries

### Query 1: Malicious Process Creation (Sysmon Event ID 1)
```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*powershell*" OR CommandLine="*cmd.exe*" OR CommandLine="*encoded*"
| table _time, host, user, ParentImage, Image, CommandLine, ProcessId, ParentProcessId
| sort - _time
