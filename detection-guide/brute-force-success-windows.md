# 🛡️ Rule: CUSTOM: Brute Force SUCCESS - Windows

---

## 📖 Description
Detects successful brute force attacks on Windows systems after multiple failed login attempts from the same source.

**Platform:** Windows  
**MITRE ATT&CK Techniques:** T1110

---

## 🔎 KQL Query

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where Account == "Domin\\UserName"
| project TimeGenerated, EventID, Computer, IpAddress, LogonType, Activity = EventData
| order by TimeGenerated asc
````

---

## 🔗 External Resources

* **VirusTotal** – [https://www.virustotal.com](https://www.virustotal.com)
  Check if the source IP, domain, or file hash is already known as malicious.

* **AbuseIPDB** – [https://www.abuseipdb.com](https://www.abuseipdb.com)
  Look up the source IP address to see community reports of brute force, spam, or malicious activity.

