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
