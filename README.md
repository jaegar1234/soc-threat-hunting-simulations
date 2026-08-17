# soc-threat-hunting-simulations
Hands-on SOC threat hunting simulation triaging simulated enterprise incidents across endpoint and network vectors. Features custom Splunk SPL queries on Sysmon logs, deep-dive Wireshark packet inspection for C2 beaconing, and phishing triage with SPF/DKIM verification, URL defanging, and hash analysis.
SOC Incident Response & Threat Hunting Portfolio

Practical security operations and threat hunting lab exercises simulating real-world enterprise incident triage across SIEM telemetry, packet analysis, and email security vectors.

---

##  Lab Scenarios & Investigation Summaries

### 1. Endpoint Triage & Process Tree Analysis (Splunk)
* **Objective:** Detect adversary execution, privilege escalation, and lateral movement from endpoint logs.
* **Key Actions:**
  * Analyzed Microsoft Sysmon telemetry (Event ID 1 for process creation, Event ID 3 for network connections).
  * Wrote custom SPL queries to isolate encoded PowerShell payloads and trace parent-child PID relationships (`OUTLOOK.EXE` -> `powershell.exe`).
  * Identified adversary persistence mechanisms and mapped tactics to **MITRE ATT&CK T1059.001**.
*  **Full Report:** [`splunk-investigations/splunk_triage_report.md`](splunk-investigations/splunk_triage_report.md)

---

### 2. Network Packet Forensics & C2 Beaconing (Wireshark)
* **Objective:** Reconstruct unencrypted network sessions and identify Command-and-Control (C2) beaconing.
* **Key Actions:**
  * Filtered raw `.pcap` files using Wireshark display filters (`http.request`, `dns.flags.response == 0`).
  * Reconstructed TCP streams to extract exfiltrated metadata and identify malicious user-agent strings.
  * Detected regular interval beaconing traffic communicating with external adversary infrastructure (`185.220.101.5`).
*  **Full Report:** [`wireshark-packet-analysis/pcap_analysis_report.md`](wireshark-packet-analysis/pcap_analysis_report.md)

---

### 3. Phishing Triage & Static Artifact Analysis
* **Objective:** Analyze suspicious `.eml` email artifacts to detect spear-phishing attempts.
* **Key Actions:**
  * Inspected raw email headers for sender spoofing, verifying `SPF: FAIL`, `DKIM: FAIL`, and `DMARC: REJECT`.
  * Defanged weaponized URLs via CyberChef (`hxxp[://]...`) to prevent accidental execution.
  * Extracted attachment cryptographic hashes (SHA-256) and correlated threat intelligence on VirusTotal and AbuseIPDB.
*  **Full Report:** [`phishing-analysis/email_triage_report.md`](phishing-analysis/email_triage_report.md)

---

##  Tools & Technologies
* **SIEM / Telemetry:** Splunk Enterprise (SPL), Microsoft Sysmon, Windows Event Logs
* **Packet Inspection:** Wireshark, tcpdump
* **Threat Intelligence & Sanitization:** VirusTotal, CyberChef, AbuseIPDB
* **Frameworks:** MITRE ATT&CK, NIST SP 800-61r2
