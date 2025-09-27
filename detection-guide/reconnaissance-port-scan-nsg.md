# 🛡️ Rule: CUSTOM: Reconnaissance – Port Scan – NSG

---

## 📖 Description
Detects port scanning activities by monitoring multiple connection attempts from a single source to numerous destination ports.

**Platform:** Network  
**MITRE ATT&CK Techniques:** T1595, T1592, T1590

---

## 🔎 KQL Query

```kql
NTANetAnalytics
| extend SrcIP = tostring(split(SrcPublicIps, "|")[0])
| where SrcIP == "[IP]"
| extend Country = tostring(Country)  // already included in your sample schema
| project TimeGenerated, SrcIP, Country, DestIp, DestPort, FlowDirection, FlowStatus
````

```kql
NTANetAnalytics
| extend SrcIP = tostring(split(SrcPublicIps, "|")[0])
| where SrcIP == "[IP]"
| summarize Attempts=count() by DestIp, DestPort, FlowStatus, bin(TimeGenerated, 10m)
| order by Attempts desc
````

---

## 🔗 External Resources

* **VirusTotal** – [https://www.virustotal.com](https://www.virustotal.com)
  Check if the source IP, domain, or file hash is already known as malicious.

* **AbuseIPDB** – [https://www.abuseipdb.com](https://www.abuseipdb.com)
  Look up the source IP address to see community reports of brute force, spam, or malicious activity.
