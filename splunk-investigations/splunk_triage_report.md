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
Finding: Host WIN-ENDPOINT-01 executed encoded PowerShell spawned by parent OUTLOOK.EXE (PID: 3120).

Query 2: External C2 Communication (Sysmon Event ID 3)
Splunk SPL
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 (ProcessId=4928 OR Image="*powershell.exe*")
| stats count, values(DestinationPort) as DstPort, sum(SourceLength) as OutboundBytes by SourceIp, DestinationIp, DestinationHostname
Finding: Outbound connections established to external malicious IP 185.220.101.5 on port 443.

3. MITRE ATT&CK Mapping
Initial Access: T1566.001 (Spearphishing Attachment)

Execution: T1059.001 (Command and Scripting Interpreter: PowerShell)

Command and Control: T1071.001 (Application Layer Protocol: Web Protocols)

4. Remediation & Containment
Isolated WIN-ENDPOINT-01 (10.0.0.45) from corporate LAN.

Terminated active process trees associated with PID 4928.

Blacklisted destination IP 185.220.101.5 at edge firewall.


---

**2. File: `wireshark-packet-analysis/pcap_analysis_report.md`**

Put **only** the network capture analysis here:

```markdown
# Incident Report: Network Traffic Analysis & C2 Inspection

## 1. Incident Overview
* **Incident ID:** IR-2026-0816-PCAP
* **Platform:** Wireshark
* **Target Protocol:** HTTP, TCP, DNS
* **Severity:** Medium / High

---

## 2. Packet Analysis Methodology & Filters

### Filter 1: HTTP Request Inspection
```text
http.request.method == "GET" or http.request.method == "POST"
Observations: Identified anomalous GET request to /update.bin hosted on an untrusted external server.

Filter 2: Reconstructed TCP Payload Stream
Action: Right-click packet -> Follow TCP Stream.

Payload Analysis: Extracted unencrypted HTTP response containing staging reverse-shell configuration.

Filter 3: DNS Beaconing Detection
Plaintext
dns.flags.response == 0
Analysis: Identified recurring 60-second interval DNS lookups resolving subdomains of c2-gateway.external-host.net.

3. Indicators of Compromise (IoCs)
C2 Host: c2-gateway.external-host.net

C2 IPv4: 185.220.101.5

Target Port: 443 / 8080


---

**3. File: `phishing-analysis/email_triage_report.md`**

Put **only** the phishing/header inspection report here:

```markdown
# Incident Report: Phishing Artifact & Header Analysis

## 1. Incident Overview
* **Incident ID:** IR-2026-0816-EML
* **Platform / Tool:** CyberChef / Mail Header Analyzer / VirusTotal
* **Artifact:** Suspicious Internal Executive Spoofing Email (.eml)
* **Category:** Spear Phishing / Credential Harvester
* **Severity:** High

---

## 2. Header Verification & Authentication
* **Claimed Sender:** `CEO Office <ceo@company.com>`
* **True Originating IP:** `198.51.100.75`
* **Reverse DNS Lookup:** `mail-relay-untrusted.attacker-net.org`
* **Authentication Results:**
  * `SPF: FAIL` (Sender IP `198.51.100.75` is not permitted by `company.com` SPF policy)
  * `DKIM: FAIL` (Signature missing or cryptographic verification failed)
  * `DMARC: FAIL` (Policy set to `p=reject`)

---

## 3. Threat Artifacts & Sanitized IoCs

### Defanged Links
* `hxxp[://]secure-alerts-portal[.]com/login/auth[.]php`
* `hxxp[://]c2-gateway[.]external-host[.]net/payload[.]bin`

### Malicious Attachment
* **File Name:** `Urgent_Q3_Review.xlsm`
* **File Type:** Microsoft Excel Macro-Enabled Worksheet
* **SHA-256 Hash:** `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
* **VirusTotal Detection Ratio:** 48/72 security engines (Trojan.Downloader / VBA.Agent)

---

## 4. Remediation & SOC Response Actions
1. **Mailbox Purge:** Queried Microsoft 365 Exchange trace logs and deleted all copies matching the unique Message-ID across enterprise inboxes.
2. **Domain/IP Ingestion:** Added sender domain `attacker-net.org` and IP `198.51.100.75` to the Secure Email Gateway (SEG) blocklist.
3. **Firewall/DNS Sinkhole:** Blocked outbound DNS requests and egress traffic to `secure-alerts-portal[.]com` at perimeter firewalls.
4. **User Security Alert:** Reset credentials for the targeted employee and scheduled an automated phishing re-training simulation.