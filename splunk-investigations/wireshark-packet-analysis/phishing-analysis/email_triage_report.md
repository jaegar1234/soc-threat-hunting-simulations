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
