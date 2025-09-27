# 🛡️ Rule: CUSTOM: Brute Force ATTEMPT - Windows

---

## 📖 Description
Identifies potential brute force attacks against Windows systems by detecting multiple failed authentication attempts.

**Platform:** Windows  
**MITRE ATT&CK Techniques:** T1110

---

## 🔎 KQL Query

```kql
SecurityEvent
| where Activity contains "4625" 
````

---

## 🔗 External Resources
* **VirusTotal** – [https://www.virustotal.com](https://www.virustotal.com)
  Check if the source IP, domain, or file hash is already known as malicious.

* **AbuseIPDB** – [https://www.abuseipdb.com](https://www.abuseipdb.com)
  Look up the source IP address to see community reports of brute force, spam, or malicious activity.