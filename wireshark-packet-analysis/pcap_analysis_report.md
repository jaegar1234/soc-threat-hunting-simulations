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